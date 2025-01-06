###
# PLEASE REPLACE 'PLACEHOLDER' VALUES
###

import sys
import os
import threading
import webbrowser
import logging
from datetime import datetime
import base64
import requests
from urllib.parse import quote
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QProgressBar, QComboBox
)
from PyQt5.QtGui import QPalette, QColor, QPixmap, QIcon
from azure.identity import InteractiveBrowserCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from msal import ConfidentialClientApplication

# Set up logging
logging.basicConfig(level=logging.DEBUG)


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class AuthWindow(QWidget):
    success_signal = pyqtSignal()
    auth_failed_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.success_signal.connect(self.success)
        self.auth_failed_signal.connect(self.auth_failed)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.logo = QLabel(self)
        pixmap = QPixmap(resource_path("logo.png"))
        if not pixmap.isNull():
            self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.logo)

        self.auth_button = QPushButton("Authenticate to Azure", self)
        self.auth_button.clicked.connect(self.authenticate)
        layout.addWidget(self.auth_button)

        self.loading_bar = QProgressBar(self)
        self.loading_bar.setRange(0, 0)
        self.loading_bar.setVisible(False)
        layout.addWidget(self.loading_bar)

        self.setLayout(layout)
        self.setWindowTitle("Admin Password")
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        self.setWindowIcon(QIcon(resource_path("logo.ico")))
        self.resize(350, 200)
        self.center_on_primary_screen()
        self.show()

    def center_on_primary_screen(self):
        screen = QApplication.primaryScreen()
        size = screen.availableGeometry()
        x = size.x() + (size.width() - self.width()) // 2
        y = size.y() + (size.height() - self.height()) // 2
        self.move(x, y)

    def authenticate(self):
        self.loading_bar.setVisible(True)
        self.auth_button.setDisabled(True)
        threading.Thread(target=self.try_authenticate).start()

    def try_authenticate(self):
        try:
            logging.debug("Starting Azure authentication...")
            self.personal_credential = InteractiveBrowserCredential(additionally_allowed_tenants=["*"])
            personal_client = SecretClient(
                vault_url="https://PLACEHOLDER.vault.azure.net",
                credential=self.personal_credential
            )
            client_id = personal_client.get_secret("PLACEHOLDER").value
            client_secret = personal_client.get_secret("PLACEHOLDER").value
            tenant_id = "PLACEHOLDER"

            self.app_credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            self.app_credential.get_token("https://management.azure.com/.default")

            self.graph_api_client = ConfidentialClientApplication(
                client_id=client_id,
                authority=f"https://login.microsoftonline.com/{tenant_id}",
                client_credential=client_secret
            )

            self.success_signal.emit()
            logging.debug("Azure authentication successful.")
        except Exception as e:
            error_message = (
                "You do not have the required permissions to access the key vault."
                if "403" in str(e)
                else "An error occurred during authentication. Please try again."
            )
            self.auth_failed_signal.emit(error_message)
            logging.error(f"Authentication failed: {e}")

    @pyqtSlot()
    def success(self):
        self.loading_bar.setVisible(False)
        self.auth_button.setDisabled(False)
        self.hide()
        self.computer_window = ComputerWindow(self.app_credential, self.graph_api_client)
        self.computer_window.show()

    @pyqtSlot(str)
    def auth_failed(self, message):
        self.loading_bar.setVisible(False)
        self.auth_button.setDisabled(False)
        QMessageBox.critical(self, "Authentication Failed", message, QMessageBox.Ok)


class ComputerWindow(QWidget):
    devices_found_signal = pyqtSignal(list)
    status_signal = pyqtSignal(str, QColor)
    secret_retrieved_signal = pyqtSignal()

    def __init__(self, credential, graph_api_client):
        super().__init__()
        self.credential = credential
        self.graph_api_client = graph_api_client
        self.secret_value = None

        self.devices_found_signal.connect(self.populate_devices)
        self.status_signal.connect(self.display_status)
        self.secret_retrieved_signal.connect(self.on_secret_retrieved)

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.logo = QLabel(self)
        pixmap = QPixmap(resource_path("logo.png"))
        if not pixmap.isNull():
            self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.logo)

        self.label = QLabel("Enter the user name:", self)
        layout.addWidget(self.label)

        self.user_name_input = QLineEdit(self)
        self.user_name_input.textChanged.connect(self.on_input_changed)
        self.user_name_input.returnPressed.connect(self.trigger_search)
        layout.addWidget(self.user_name_input)

        self.search_button = QPushButton("Search", self)
        self.search_button.clicked.connect(self.search_devices)
        self.search_button.setDisabled(True)
        layout.addWidget(self.search_button)

        self.device_label = QLabel("Select a device:", self)
        self.device_label.setVisible(False)
        layout.addWidget(self.device_label)

        self.device_dropdown = QComboBox(self)
        self.device_dropdown.setDisabled(True)
        self.device_dropdown.currentIndexChanged.connect(self.on_device_selection_changed)
        layout.addWidget(self.device_dropdown)

        self.button = QPushButton("Get Secret", self)
        self.button.clicked.connect(self.get_secret)
        self.button.setDisabled(True)
        layout.addWidget(self.button)

        self.copy_button = QPushButton("Copy Secret", self)
        self.copy_button.clicked.connect(self.copy_secret)
        self.copy_button.setDisabled(True)
        layout.addWidget(self.copy_button)

        self.share_button = QPushButton("Share Securely", self)
        self.share_button.clicked.connect(self.share_secret)
        self.share_button.setDisabled(True)
        layout.addWidget(self.share_button)

        self.loading_bar = QProgressBar(self)
        self.loading_bar.setRange(0, 0)
        self.loading_bar.setVisible(False)
        layout.addWidget(self.loading_bar)

        self.result = QLabel("", self)
        layout.addWidget(self.result)

        self.setLayout(layout)
        self.setWindowTitle("Admin Password")
        self.resize(400, 400)
        self.center_on_primary_screen()

    def center_on_primary_screen(self):
        screen = QApplication.primaryScreen()
        size = screen.availableGeometry()
        x = size.x() + (size.width() - self.width()) // 2
        y = size.y() + (size.height() - self.height()) // 2
        self.move(x, y)

    def on_input_changed(self):
        self.search_button.setDisabled(not self.user_name_input.text().strip())

    def trigger_search(self):
        if self.search_button.isEnabled():
            self.search_button.click()

    def on_device_selection_changed(self):
        self.secret_value = None
        self.result.setText("")
        self.button.setDisabled(False)
        self.copy_button.setDisabled(True)
        self.share_button.setDisabled(True)

    def search_devices(self):
        self.result.setText("")
        user_name = self.user_name_input.text().strip().replace(" ", ".").replace("'", "''")
        self.search_button.setDisabled(True)
        self.loading_bar.setVisible(True)
        threading.Thread(target=self.retrieve_devices, args=(user_name,)).start()

    def get_graph_api_token(self):
        token = self.graph_api_client.acquire_token_silent(
            ["https://graph.microsoft.com/.default"], account=None
        )
        if not token:
            token = self.graph_api_client.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )
        return token

    def retrieve_devices(self, user_name):
        try:
            logging.debug(f"Searching for devices for user: {user_name}")
            token = self.get_graph_api_token()

            headers = {"Authorization": f"Bearer {token['access_token']}"}
            filter_query = (
                f"contains(userPrincipalName,'{user_name}') and "
                "(operatingSystem eq 'Windows' or operatingSystem eq 'macOS')"
            )
            url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
            params = {"$filter": filter_query}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            logging.debug(f"Response from managedDevices: {response.status_code}")
            logging.debug(f"Response Body: {response.text}")
            response.raise_for_status()

            devices = response.json().get("value", [])
            if devices:
                self.devices_found_signal.emit(devices)
            else:
                self.status_signal.emit("No devices found.", QColor("red"))
                logging.debug("No devices found.")
        except Exception as e:
            self.status_signal.emit(f"Error: {e}", QColor("red"))
            logging.error(f"Error searching for devices: {e}")
        finally:
            self.loading_bar.setVisible(False)
            self.search_button.setDisabled(False)

    @pyqtSlot(list)
    def populate_devices(self, devices):
        self.device_label.setVisible(True)
        self.device_dropdown.clear()
        for device in devices:
            self.device_dropdown.addItem(f"{device['deviceName']} ({device['operatingSystem']})", device)
        self.device_dropdown.setDisabled(False)
        self.button.setDisabled(False)

    @pyqtSlot(str, QColor)
    def display_status(self, message, color):
        self.result.setText(message)
        palette = self.result.palette()
        palette.setColor(QPalette.WindowText, color)
        self.result.setPalette(palette)

    def get_secret(self):
        selected_device = self.device_dropdown.currentData()
        if not selected_device:
            self.display_status("No device selected.", QColor("red"))
            logging.error("No device selected.")
            return

        self.loading_bar.setVisible(True)
        self.button.setDisabled(True)
        self.copy_button.setDisabled(True)
        self.share_button.setDisabled(True)

        if selected_device["operatingSystem"] == "macOS":
            threading.Thread(
                target=self.retrieve_secret_from_vault, args=(selected_device["deviceName"],)
            ).start()
        elif selected_device["operatingSystem"] == "Windows":
            threading.Thread(
                target=self.retrieve_secret_from_intune, args=(selected_device["id"],)
            ).start()

    def retrieve_secret_from_vault(self, device_name):
        try:
            vault_url = "https://PLACEHOLDER.vault.azure.net"
            client = SecretClient(vault_url=vault_url, credential=self.credential)
            secret = client.get_secret(device_name)
            self.secret_value = secret.value
            self.status_signal.emit("macOS secret retrieved.", QColor("green"))
            logging.debug(f"macOS secret retrieved: {self.secret_value}")
            self.secret_retrieved_signal.emit()
        except Exception as e:
            error_msg = f"Error retrieving macOS secret: {e}"
            self.status_signal.emit(error_msg, QColor("red"))
            logging.error(error_msg)
        finally:
            self.loading_bar.setVisible(False)
            self.button.setDisabled(False)

    def retrieve_secret_from_intune(self, intune_device_id):
        try:
            logging.debug("Starting retrieval for Windows device...")
            token = self.get_graph_api_token()

            headers = {
                "Authorization": f"Bearer {token['access_token']}",
                "ocp-client-name": "AdminClient",
                "ocp-client-version": "1.0"
            }

            # Fetch device details to get the Azure AD Device ID
            url_device_details = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{intune_device_id}"
            device_response = requests.get(url_device_details, headers=headers, timeout=10)
            logging.debug(f"Response from managedDevices: {device_response.status_code}")
            logging.debug(f"Response Body: {device_response.text}")
            device_response.raise_for_status()

            device_data = device_response.json()
            azure_ad_device_id = device_data.get("azureADDeviceId")
            logging.debug(f"Azure AD Device ID: {azure_ad_device_id}")

            if not azure_ad_device_id:
                self.status_signal.emit("Azure AD Device ID not found for this device.", QColor("red"))
                logging.error("Azure AD Device ID not found.")
                return

            # Fetch Local Admin Password using the Azure AD Device ID
            url_local_credentials = f"https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials/{azure_ad_device_id}?$select=credentials"
            credentials_response = requests.get(url_local_credentials, headers=headers, timeout=10)
            logging.debug(f"Response from deviceLocalCredentials: {credentials_response.status_code}")
            logging.debug(f"Response Body: {credentials_response.text}")
            credentials_response.raise_for_status()

            credentials_data = credentials_response.json()
            credentials = credentials_data.get("credentials", [])
            if credentials:
                # Sort credentials by backupDateTime and get the most recent one
                latest_credential = max(
                    credentials,
                    key=lambda x: datetime.fromisoformat(x["backupDateTime"].replace('Z', '+00:00'))
                )
                password_base64 = latest_credential.get("passwordBase64")
                if password_base64:
                    password = base64.b64decode(password_base64).decode('utf-8')
                    self.secret_value = password
                    self.status_signal.emit("Windows secret retrieved.", QColor("green"))
                    logging.debug(f"Windows secret retrieved: {password}")
                    self.secret_retrieved_signal.emit()
                else:
                    self.status_signal.emit("Password not found in the latest credential.", QColor("red"))
                    logging.error("Password missing in the latest credential.")
            else:
                self.status_signal.emit("No credentials found for this device.", QColor("red"))
                logging.error("No credentials found in the response.")
        except requests.exceptions.HTTPError as e:
            error_details = e.response.text if hasattr(e, 'response') and e.response else str(e)
            error_msg = f"HTTP Error: {e}, Response Body: {error_details}"
            self.status_signal.emit(f"Error retrieving Windows secret: {e}", QColor("red"))
            logging.error(error_msg)
        except Exception as e:
            error_msg = f"General Exception: {e}"
            self.status_signal.emit(f"Error retrieving Windows secret: {e}", QColor("red"))
            logging.error(error_msg)
        finally:
            self.loading_bar.setVisible(False)
            self.button.setDisabled(False)

    @pyqtSlot()
    def on_secret_retrieved(self):
        self.copy_button.setDisabled(False)
        self.share_button.setDisabled(False)

    def copy_secret(self):
        if self.secret_value:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.secret_value)
            self.display_status("Secret copied.", QColor("green"))
            logging.debug("Secret copied to clipboard.")

    def share_secret(self):
        webbrowser.open("https://exemple.com/")
        logging.debug("Sharing secret securely.")


def main():
    app = QApplication(sys.argv)
    auth_window = AuthWindow()
    auth_window.show() 
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
