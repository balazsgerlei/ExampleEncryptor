package com.example.encryptor.ui

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class MainViewModel: ViewModel() {

    sealed class UiEvent {
        data class ShowBiometricPromptForEncryption(
            val cryptoObject: BiometricPrompt.CryptoObject? = null
        ): UiEvent()
        data class ShowBiometricPromptForDecryption(
            val cryptoObject: BiometricPrompt.CryptoObject? = null
        ): UiEvent()
        data object FailedToShowBiometricPrompt: UiEvent()
        data class AuthenticationError(
            val errorCode: Int,
            val errorString: CharSequence
        ): UiEvent()
        data class EncryptionSucceeded(
            val encryptedText: String,
        ): UiEvent()
        data class DecryptionSucceeded(
            val plainText: String,
        ): UiEvent()
        data object AuthenticationFailed: UiEvent()
        data object EncryptionFailed: UiEvent()
        data object DecryptionFailed: UiEvent()
    }

    private val _eventChannel = Channel<UiEvent>(Channel.BUFFERED)
    val eventChannel = _eventChannel.receiveAsFlow()

    private val _encryptedBytes = MutableStateFlow<ByteArray?>(null)
    val encryptedText: Flow<String?> = _encryptedBytes.asStateFlow().map { encryptedBytes -> encryptedBytes?.decodeToString() }

    private var ivUsedForEncryption: ByteArray? = null
    private var cryptoObject: BiometricPrompt.CryptoObject? = null

    private val keystore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun requestEncryption(
        useCryptoObject: Boolean,
        requireUserAuthentication: Boolean,
    ) {
        if (useCryptoObject) {
            tryCreatingCryptoObject(
                requireUserAuthentication,
                cipherOperationMode = Cipher.ENCRYPT_MODE,
                ivParameterSpec = null,
                onCryptoObjectCreated = { cryptoObject ->
                    this.cryptoObject = cryptoObject
                    viewModelScope.launch {
                        _eventChannel.send(
                            UiEvent.ShowBiometricPromptForEncryption(cryptoObject)
                        )
                    }
                },
                onCannotCreateCryptoObject = {
                    viewModelScope.launch {
                        _eventChannel.send(UiEvent.FailedToShowBiometricPrompt)
                    }
                }
            )
        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.ShowBiometricPromptForEncryption())
            }
        }
    }

    fun requestDecryption(
        useCryptoObject: Boolean,
        requireUserAuthentication: Boolean,
    ) {
        if (useCryptoObject) {
            tryCreatingCryptoObject(
                requireUserAuthentication,
                cipherOperationMode = Cipher.DECRYPT_MODE,
                ivParameterSpec = IvParameterSpec(ivUsedForEncryption),
                onCryptoObjectCreated = { cryptoObject ->
                    this.cryptoObject = cryptoObject
                    viewModelScope.launch {
                        _eventChannel.send(
                            UiEvent.ShowBiometricPromptForDecryption(cryptoObject)
                        )
                    }
                },
                onCannotCreateCryptoObject = {
                    viewModelScope.launch {
                        _eventChannel.send(UiEvent.FailedToShowBiometricPrompt)
                    }
                }
            )
        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.ShowBiometricPromptForDecryption())
            }
        }
    }

    fun onAuthenticationError(errorCode: Int, errorString: CharSequence) = viewModelScope.launch {
        _eventChannel.send(UiEvent.AuthenticationError(errorCode, errorString))
    }

    fun onAuthenticationForEncryptionSucceeded(
        plainText: String,
        requireUserAuthentication: Boolean,
        cryptoObjectFromResult: BiometricPrompt.CryptoObject? = null
    ) {
        if (cryptoObject != null) {
            val cipherFromResult = cryptoObjectFromResult?.cipher
            if (cipherFromResult == cryptoObject?.cipher) {
                encryptUsingCipherFromResult(plainText, requireUserAuthentication, cipherFromResult)
            } else {
                viewModelScope.launch {
                    _eventChannel.send(UiEvent.AuthenticationFailed)
                }
            }
            cryptoObject = null
        } else {
            encryptByCreatingNewCipher(plainText, requireUserAuthentication)
        }
    }

    fun onAuthenticationForDecryptionSucceeded(
        requireUserAuthentication: Boolean,
        cryptoObjectFromResult: BiometricPrompt.CryptoObject? = null
    ) {
        val encryptedBytes = _encryptedBytes.value
        if (encryptedBytes != null) {
            if (cryptoObject != null) {
                val cipherFromResult = cryptoObjectFromResult?.cipher
                if (cipherFromResult == cryptoObject?.cipher) {
                    decryptUsingCipherFromResult(encryptedBytes, requireUserAuthentication, cipherFromResult)
                } else {
                    viewModelScope.launch {
                        _eventChannel.send(UiEvent.AuthenticationFailed)
                    }
                }
                cryptoObject = null
            } else {
                decryptByCreatingNewCipher(encryptedBytes, requireUserAuthentication)
            }
        }
    }

    fun onAuthenticationFailed() = viewModelScope.launch {
        _eventChannel.send(UiEvent.AuthenticationFailed)
    }

    private fun tryCreatingCryptoObject(
        requireUserAuthentication: Boolean,
        cipherOperationMode: Int,
        ivParameterSpec: IvParameterSpec?,
        onCryptoObjectCreated: (BiometricPrompt.CryptoObject) -> Unit,
        onCannotCreateCryptoObject: () -> Unit,
    ) {
        val cipher = createCipher()
        val secretKeyAlias = if(requireUserAuthentication) KEY_ALIAS_REQUIRING_AUTHENTICATION else KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION
        val secretKey = getSecretKey(secretKeyAlias) ?: generateKey(secretKeyAlias, requireUserAuthentication)
        if (cipher != null && initCipher(cipher, secretKey, cipherOperationMode, ivParameterSpec)) {
            onCryptoObjectCreated(BiometricPrompt.CryptoObject(cipher))
        } else {
            onCannotCreateCryptoObject()
        }
    }

    private fun encryptUsingCipherFromResult(
        plainText: String,
        requireUserAuthentication: Boolean,
        cipherFromResult: Cipher?,
    ) {
        val secretKeyAlias = if(requireUserAuthentication) KEY_ALIAS_REQUIRING_AUTHENTICATION else KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION
        val secretKey = getSecretKey(secretKeyAlias)
        if (cipherFromResult != null && secretKey != null) {
            ivUsedForEncryption = cipherFromResult.iv
            encrypt(plainText.encodeToByteArray(), cipherFromResult).let {
                _encryptedBytes.value = it
                viewModelScope.launch {
                    _eventChannel.send(UiEvent.EncryptionSucceeded(it.decodeToString()))
                }
            }

        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.EncryptionFailed)
            }
        }
    }

    private fun encryptByCreatingNewCipher(
        plainText: String,
        requireUserAuthentication: Boolean,
    ) {
        val cipher = createCipher()
        val secretKeyAlias = if(requireUserAuthentication) KEY_ALIAS_REQUIRING_AUTHENTICATION else KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION
        val secretKey = getSecretKey(secretKeyAlias) ?: generateKey(secretKeyAlias)
        if (cipher != null && secretKey != null
            && initCipher(cipher, secretKey, Cipher.ENCRYPT_MODE)) {
            ivUsedForEncryption = cipher.iv
            encrypt(plainText.encodeToByteArray(), cipher).let {
                _encryptedBytes.value = it
                viewModelScope.launch {
                    _eventChannel.send(UiEvent.EncryptionSucceeded(it.decodeToString()))
                }
            }
        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.EncryptionFailed)
            }
        }
    }

    private fun decryptUsingCipherFromResult(
        encryptedBytes: ByteArray,
        requireUserAuthentication: Boolean,
        cipherFromResult: Cipher?
    ) {
        val secretKeyAlias = if(requireUserAuthentication) KEY_ALIAS_REQUIRING_AUTHENTICATION else KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION
        val secretKey = getSecretKey(secretKeyAlias)
        if (cipherFromResult != null && secretKey != null) {
            val decryptedBytes = decrypt(encryptedBytes, cipherFromResult)
            viewModelScope.launch {
                _eventChannel.send(UiEvent.DecryptionSucceeded(decryptedBytes.decodeToString()))
            }
            ivUsedForEncryption = null
            _encryptedBytes.value = null
        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.DecryptionFailed)
            }
        }
    }

    private fun decryptByCreatingNewCipher(
        encryptedBytes: ByteArray,
        requireUserAuthentication: Boolean,
    ) {
        val cipher = createCipher()
        val secretKeyAlias = if(requireUserAuthentication) KEY_ALIAS_REQUIRING_AUTHENTICATION else KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION
        val secretKey = getSecretKey(secretKeyAlias)
        if (cipher != null && secretKey != null
            && initCipher(cipher, secretKey, Cipher.DECRYPT_MODE, IvParameterSpec(ivUsedForEncryption))) {
            val decryptedBytes = decrypt(encryptedBytes, cipher)
            viewModelScope.launch {
                _eventChannel.send(UiEvent.DecryptionSucceeded(decryptedBytes.decodeToString()))
            }
            ivUsedForEncryption = null
            _encryptedBytes.value = null
        } else {
            viewModelScope.launch {
                _eventChannel.send(UiEvent.DecryptionFailed)
            }
        }
    }

    private fun createKeyGenParameterSpec(
        alias: String,
        userAuthenticationRequired: Boolean
    ) = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(BLOCK_MODE)
        .setEncryptionPaddings(ENCRYPTION_PADDING)
        .setUserAuthenticationRequired(userAuthenticationRequired)
        /*.apply {
            if (userAuthenticationRequired) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        100,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(100)
                }
            }
        }*/
        .setRandomizedEncryptionRequired(true)
        .build()

    private fun generateKey(alias: String, userAuthenticationRequired: Boolean = false): SecretKey =
        KeyGenerator.getInstance(KEY_ALGORITHM).run {
            val keyGenParameterSpec = createKeyGenParameterSpec(alias, userAuthenticationRequired)
            init(keyGenParameterSpec)
            generateKey()
        }

    private fun getSecretKey(alias: String) = keystore.getKey(alias, null) as? SecretKey

    private fun createCipher(): Cipher? {
        try {
            return Cipher.getInstance(TRANSFORMATION)
        } catch (ex: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to create Cipher", ex)
        } catch (ex: NoSuchPaddingException) {
            throw RuntimeException("Failed to create Cipher", ex)
        }
    }

    private fun initCipher(
        cipher: Cipher,
        secretKey: SecretKey,
        operationMode: Int,
        ivParameterSpec: IvParameterSpec? = null
    ): Boolean {
        try {
            if (ivParameterSpec != null) {
                cipher.init(operationMode, secretKey, ivParameterSpec)
            } else {
                cipher.init(operationMode, secretKey)
            }
            return true
        } catch (_: KeyPermanentlyInvalidatedException) {
            return false
        } catch (ex: KeyStoreException) {
            throw RuntimeException("Failed to create Cipher", ex)
        } catch (ex: UnrecoverableKeyException) {
            throw RuntimeException("Failed to create Cipher", ex)
        } catch (ex: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to create Cipher", ex)
        } catch (ex: Exception) {
            throw RuntimeException("Failed to create Cipher", ex)
        }
    }

    private fun encrypt(bytes: ByteArray, encryptCipher: Cipher): ByteArray =
        encryptCipher.doFinal(bytes)

    private fun decrypt(bytes: ByteArray, decryptCipher: Cipher): ByteArray =
        decryptCipher.doFinal(bytes)

    companion object {
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val TRANSFORMATION = "$KEY_ALGORITHM/$BLOCK_MODE/$ENCRYPTION_PADDING"

        const val KEY_ALIAS_WITHOUT_REQUIRING_AUTHENTICATION = "key_without_requiring_user_authentication"
        const val KEY_ALIAS_REQUIRING_AUTHENTICATION = "key_requiring_user_authentication"
    }


}
