package com.example.encryptor

import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.AuthenticationRequest
import androidx.biometric.AuthenticationResult
import androidx.biometric.AuthenticationResultLauncher
import androidx.biometric.BiometricPrompt
import androidx.biometric.registerForAuthenticationResult
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.encryptor.ui.MainViewModel
import com.example.encryptor.ui.theme.ExampleEncryptorTheme

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            ExampleEncryptorTheme {
                var plainText by rememberSaveable { mutableStateOf("Test") }
                var useCryptoObjectChecked by remember { mutableStateOf(false) }
                var requireUserAuthenticationChecked by remember { mutableStateOf(false) }
                val encryptedText by viewModel.encryptedText.collectAsState("")

                val authenticationResultLauncher = registerForAuthenticationResult { result ->
                    when(result) {
                        is AuthenticationResult.Error -> {
                            viewModel.onAuthenticationError(result.errorCode, result.errString)
                        }
                        is AuthenticationResult.Success -> {
                            if (plainText != null && plainText.isNotBlank()) {
                                Toast.makeText(this@MainActivity,
                                    "Authentication for ENCRYPTION succeeded",
                                    Toast.LENGTH_SHORT)
                                    .show()
                                viewModel.onAuthenticationForEncryptionSucceeded(
                                    plainText, requireUserAuthenticationChecked, result.crypto
                                )
                            } else {
                                Toast.makeText(this@MainActivity,
                                    "Authentication for DECRYPTION succeeded",
                                    Toast.LENGTH_SHORT)
                                    .show()
                                viewModel.onAuthenticationForDecryptionSucceeded(
                                    requireUserAuthenticationChecked, result.crypto
                                )
                            }
                        }
                    }
                }

                LaunchedEffect(Unit) {
                    viewModel.eventChannel.collect { event ->
                        when(event) {
                            is MainViewModel.UiEvent.ShowBiometricPromptForEncryption -> {
                                showBiometricPromptForEncryption(
                                    authenticationResultLauncher,
                                    cryptoObject = event.cryptoObject
                                )
                            }
                            is MainViewModel.UiEvent.ShowBiometricPromptForDecryption -> {
                                showBiometricPromptForDecryption(
                                    authenticationResultLauncher,
                                    cryptoObject = event.cryptoObject
                                )
                            }
                            is MainViewModel.UiEvent.FailedToShowBiometricPrompt -> {
                                Toast.makeText(this@MainActivity,
                                    "Could not show the Biometric Prompt",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.AuthenticationError -> {
                                Toast.makeText(this@MainActivity,
                                    "Authentication error: ${event.errorString}",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.EncryptionSucceeded -> {
                                plainText = ""
                                Toast.makeText(this@MainActivity,
                                    "Encryption succeeded!",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.DecryptionSucceeded -> {
                                plainText = event.plainText
                                Toast.makeText(this@MainActivity,
                                    "Decryption succeeded!",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.AuthenticationFailed -> {
                                Toast.makeText(this@MainActivity,
                                    "Authentication failed",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.EncryptionFailed -> {
                                Toast.makeText(this@MainActivity,
                                    "Encryption failed",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                            is MainViewModel.UiEvent.DecryptionFailed -> {
                                Toast.makeText(this@MainActivity,
                                    "Decryption failed",
                                    Toast.LENGTH_SHORT)
                                    .show()
                            }
                        }
                    }
                }

                ExampleEncryptorScreen(
                    plainText = plainText,
                    onPlainTextChange = { plainText = it },
                    onClearPlainTextClicked = { plainText = "" },
                    useCryptoObjectChecked = useCryptoObjectChecked,
                    onUseCryptoObjectCheckedChange = { useCryptoObjectChecked = it },
                    requireUserAuthenticationChecked = requireUserAuthenticationChecked,
                    onRequireUserAuthenticationChecked = { requireUserAuthenticationChecked = it },
                    onEncryptClick = {
                        viewModel.requestEncryption(
                            useCryptoObjectChecked,
                            requireUserAuthenticationChecked
                        )
                    },
                    onDecryptClick = {
                        viewModel.requestDecryption(
                            useCryptoObjectChecked,
                            requireUserAuthenticationChecked
                        )
                    },
                    encryptedText = encryptedText,
                )
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun ExampleEncryptorScreen(
        plainText: String,
        onPlainTextChange: (String) -> Unit,
        onClearPlainTextClicked: () -> Unit,
        useCryptoObjectChecked: Boolean,
        onUseCryptoObjectCheckedChange: ((Boolean) -> Unit)?,
        requireUserAuthenticationChecked: Boolean,
        onRequireUserAuthenticationChecked: ((Boolean) -> Unit)?,
        onEncryptClick: () -> Unit,
        onDecryptClick: () -> Unit,
        encryptedText: String?,
    ) {

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Example Encryptor") }
                )
            },
            modifier = Modifier.fillMaxSize()
        ) { innerPadding ->
            Column (
                modifier = Modifier.padding(innerPadding),
            ) {
                OutlinedTextField(
                    label = { Text("Plain Text") },
                    value = plainText,
                    onValueChange = onPlainTextChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp),
                    trailingIcon = {
                        if (plainText.isNotBlank()) {
                            Icon(Icons.Default.Clear,
                                contentDescription = "Clear text",
                                modifier = Modifier.clickable(onClick = onClearPlainTextClicked)
                            )
                        }
                    }
                )
                Row (
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp)
                ) {
                    Switch(
                        checked = useCryptoObjectChecked,
                        onCheckedChange = onUseCryptoObjectCheckedChange,
                    )
                    Text(
                        text = "Use CryptoObject",
                        modifier = Modifier
                            .weight(1f)
                            .padding(start = 8.dp)
                    )
                }
                if (useCryptoObjectChecked) {
                    Row (
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp)
                    ) {
                        Switch(
                            checked = requireUserAuthenticationChecked,
                            onCheckedChange = onRequireUserAuthenticationChecked,
                        )
                        Text(
                            text = "Require User Authentication",
                            modifier = Modifier
                                .weight(1f)
                                .padding(start = 8.dp)
                        )
                    }
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(start = 16.dp, top = 8.dp, end = 16.dp)
                ) {
                    ElevatedButton (
                        enabled = plainText.isNotBlank(),
                        onClick = onEncryptClick,
                        modifier = Modifier
                            .padding(start = 16.dp, top = 8.dp, end = 16.dp)
                    ) {
                        Text("Encrypt")
                    }
                    ElevatedButton (
                        enabled = encryptedText != null && encryptedText.isNotBlank(),
                        onClick = onDecryptClick,
                        modifier = Modifier
                            .padding(start = 16.dp, top = 8.dp, end = 16.dp)
                    ) {
                        Text("Decrypt")
                    }
                }
                OutlinedTextField(
                    label = { Text("Encrypted Text") },
                    value = encryptedText ?: "",
                    onValueChange = { },
                    enabled = false,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, top = 8.dp, end = 16.dp)
                )
            }
        }
    }

    private fun createAuthenticationRequest(
        title: String,
        cryptoObject: BiometricPrompt.CryptoObject? = null,
    ) = AuthenticationRequest.Biometric.Builder(title,
        authFallback = AuthenticationRequest.Biometric.Fallback.NegativeButton("Cancel")
    )
        .apply {
            if (cryptoObject != null) {
                setMinStrength(AuthenticationRequest.Biometric.Strength.Class3(cryptoObject))
            } else {
                setMinStrength(AuthenticationRequest.Biometric.Strength.Class2)
            }
        }
        .build()

    private fun showBiometricPromptForEncryption(
        authenticationResultLauncher: AuthenticationResultLauncher,
        cryptoObject: BiometricPrompt.CryptoObject? = null
    ) {
        val title = "Authenticate for encryption"
        createAuthenticationRequest(title, cryptoObject).let {
            authenticationResultLauncher.launch(it)
        }
    }

    private fun showBiometricPromptForDecryption(
        authenticationResultLauncher: AuthenticationResultLauncher,
        cryptoObject: BiometricPrompt.CryptoObject? = null
    ) {
        val title = "Authenticate for decryption"
        createAuthenticationRequest(title, cryptoObject).let {
            authenticationResultLauncher.launch(it)
        }
    }
}
