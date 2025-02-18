import sys
import os
import logging
import base64
import requests
from datetime import datetime
from urllib.parse import quote

from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal, QRunnable, QThreadPool, QObject
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QProgressBar, QComboBox
)
from PyQt5.QtGui import QPalette, QColor, QPixmap, QIcon

from azure.identity import InteractiveBrowserCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from msal import ConfidentialClientApplication
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError

# --------------------------
# Configuration / Constants
# --------------------------
AUTH_WINDOW_SIZE = (350, 200)
COMPUTER_WINDOW_SIZE = (450, 400)
KV_CREDENTIALS_URL = "https://<vault_name>.vault.azure.net/"
STORAGE_TABLE_ENDPOINT = "https://<table_name>.table.core.windows.net/"
TENANT_ID = "<tenant_id>"

# --------------------------
# Logging Setup
# --------------------------
logging.basicConfig(level=logging.DEBUG)

# --------------------------
# Helper Functions
# --------------------------
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def center_window(window):
    """Center a given window on the primary screen."""
    screen = QApplication.primaryScreen()
    geom = screen.availableGeometry()
    x = geom.x() + (geom.width() - window.width()) // 2
    y = geom.y() + (geom.height() - window.height()) // 2
    window.move(x, y)

# --------------------------
# Worker Classes for Background Tasks
# --------------------------
class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(tuple)

class Worker(QRunnable):
    """
    Worker thread for running a function in the background.
    """
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.signals.error.emit((e, tb))
        else:
            self.signals.finished.emit(result)

# --------------------------
# Main Application Windows
# --------------------------
class AuthWindow(QWidget):
    success_signal = pyqtSignal()
    auth_failed_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.threadpool = QThreadPool()
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
        self.setWindowTitle("<title>")
        self.setWindowIcon(QIcon(resource_path("logo.ico")))
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        self.setFixedSize(*AUTH_WINDOW_SIZE)
        center_window(self)
        self.show()

    def authenticate(self):
        self.loading_bar.setVisible(True)
        self.auth_button.setDisabled(True)
        worker = Worker(self.try_authenticate)
        worker.signals.finished.connect(lambda _: self.success_signal.emit())
        worker.signals.error.connect(self.on_authenticate_error)
        self.threadpool.start(worker)

    def try_authenticate(self):
        logging.debug("Starting Azure authentication...")
        personal_credential = InteractiveBrowserCredential(additionally_allowed_tenants=["*"])
        personal_client = SecretClient(
            vault_url=KV_CREDENTIALS_URL,
            credential=personal_credential
        )
        client_id = personal_client.get_secret("<client_id>").value
        client_secret = personal_client.get_secret("<client_secret>").value

        self.app_credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=client_id,
            client_secret=client_secret
        )
        self.app_credential.get_token("https://management.azure.com/.default")

        self.graph_api_client = ConfidentialClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{TENANT_ID}",
            client_credential=client_secret
        )
        return True

    def on_authenticate_error(self, error_tuple):
        exception, tb = error_tuple
        error_message = ("You do not have the required permissions to access the key vault."
                         if "403" in str(exception)
                         else "An error occurred during authentication. Please try again.")
        self.auth_failed_signal.emit(error_message)
        logging.error(f"Authentication failed: {exception}\n{tb}")

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
        self.threadpool = QThreadPool()
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

        self.label = QLabel("Enter user email, device name, or serial number:", self)
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
        self.setWindowTitle("<title>")
        self.setFixedSize(*COMPUTER_WINDOW_SIZE)
        center_window(self)

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
        search_term = self.user_name_input.text().strip().replace("'", "''")
        self.search_button.setDisabled(True)
        self.loading_bar.setVisible(True)
        worker = Worker(self.retrieve_devices, search_term)
        worker.signals.finished.connect(self.on_devices_found)
        worker.signals.error.connect(lambda err: self.on_search_error(err))
        self.threadpool.start(worker)

    def on_devices_found(self, result):
        self.loading_bar.setVisible(False)
        self.search_button.setDisabled(False)
        if not result:
            self.status_signal.emit("No devices found.", QColor("red"))
        else:
            self.devices_found_signal.emit(result)

    def on_search_error(self, error_tuple):
        exception, tb = error_tuple
        self.loading_bar.setVisible(False)
        self.search_button.setDisabled(False)
        self.status_signal.emit(f"Error: {exception}", QColor("red"))
        logging.error(f"Error searching for devices: {exception}\n{tb}")

    def get_graph_api_token(self):
        token = self.graph_api_client.acquire_token_silent(["https://graph.microsoft.com/.default"], account=None)
        if not token:
            token = self.graph_api_client.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        return token

    def retrieve_devices(self, search_term):
        logging.debug(f"Searching for devices with search term: {search_term}")
        token = self.get_graph_api_token()
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        base_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        filters = [
            f"contains(userPrincipalName, '{search_term}')",
            f"contains(deviceName, '{search_term}')",
            f"contains(serialNumber, '{search_term}')"
        ]
        all_devices = []
        for f in filters:
            query = f"({f} and (operatingSystem eq 'Windows' or operatingSystem eq 'macOS'))"
            params = {"$filter": query}
            logging.debug(f"Querying with filter: {query}")
            response = requests.get(base_url, headers=headers, params=params, timeout=10)
            logging.debug(f"Response from managedDevices: {response.status_code}")
            logging.debug(f"Response Body: {response.text}")
            response.raise_for_status()
            devices = response.json().get("value", [])
            all_devices.extend(devices)
        unique_devices = {device['id']: device for device in all_devices}.values()
        return list(unique_devices)

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
        pal = self.result.palette()
        pal.setColor(QPalette.WindowText, color)
        self.result.setPalette(pal)

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
            worker = Worker(self.retrieve_secret_from_vault, selected_device["deviceName"])
            worker.signals.finished.connect(lambda res: self._secret_success(res, "macOS secret retrieved."))
            worker.signals.error.connect(self._secret_error)
            self.threadpool.start(worker)
        elif selected_device["operatingSystem"] == "Windows":
            worker = Worker(self.retrieve_secret_from_intune, selected_device["id"])
            worker.signals.finished.connect(lambda res: self._secret_success(res, "Windows secret retrieved."))
            worker.signals.error.connect(self._secret_error)
            self.threadpool.start(worker)

    def _secret_success(self, secret, success_message):
        self.secret_value = secret
        self.status_signal.emit(success_message, QColor("green"))
        self.secret_retrieved_signal.emit()
        self.loading_bar.setVisible(False)

    def _secret_error(self, error_tuple):
        exception, tb = error_tuple
        msg = str(exception)
        if isinstance(exception, ResourceNotFoundError):
            msg = "Computer not found in database."
        self.status_signal.emit(msg, QColor("red"))
        logging.error(f"Secret retrieval error: {exception}\n{tb}")
        self.loading_bar.setVisible(False)

    def retrieve_secret_from_vault(self, device_name):
        logging.debug(f"Retrieving macOS secret for device: {device_name} from Storage Table")
        table_service = TableServiceClient(
            endpoint=STORAGE_TABLE_ENDPOINT,
            credential=self.credential
        )
        table_client = table_service.get_table_client(table_name="<table>")
        entity = table_client.get_entity(partition_key="macOS", row_key=device_name)
        logging.debug(f"Retrieved entity: {entity}")
        password = entity.get("Password")
        if not password:
            raise ValueError("Password not found in storage table.")
        return str(password)

    def retrieve_secret_from_intune(self, intune_device_id):
        logging.debug("Starting retrieval for Windows device...")
        token = self.get_graph_api_token()
        headers = {
            "Authorization": f"Bearer {token['access_token']}",
            "ocp-client-name": "adminClient",
            "ocp-client-version": "1.0"
        }
        url_device_details = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{intune_device_id}"
        device_response = requests.get(url_device_details, headers=headers, timeout=10)
        logging.debug(f"Response from managedDevices: {device_response.status_code}")
        logging.debug(f"Response Body: {device_response.text}")
        device_response.raise_for_status()
        device_data = device_response.json()
        azure_ad_device_id = device_data.get("azureADDeviceId")
        logging.debug(f"Azure AD Device ID: {azure_ad_device_id}")
        if not azure_ad_device_id:
            raise ValueError("Azure AD Device ID not found for this device.")
        url_local_credentials = f"https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials/{azure_ad_device_id}?$select=credentials"
        credentials_response = requests.get(url_local_credentials, headers=headers, timeout=10)
        logging.debug(f"Response from deviceLocalCredentials: {credentials_response.status_code}")
        logging.debug(f"Response Body: {credentials_response.text}")
        credentials_response.raise_for_status()
        credentials_data = credentials_response.json()
        credentials = credentials_data.get("credentials", [])
        if not credentials:
            raise ValueError("No credentials found for this device.")
        latest_credential = max(
            credentials,
            key=lambda x: datetime.fromisoformat(x["backupDateTime"].replace('Z', '+00:00'))
        )
        password_base64 = latest_credential.get("passwordBase64")
        if not password_base64:
            raise ValueError("Password not found in the latest credential.")
        password = base64.b64decode(password_base64).decode('utf-8')
        return password

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
        webbrowser.open("https://microsoft.com/")
        logging.debug("Sharing secret securely.")

# --------------------------
# Main Function
# --------------------------
def main():
    app = QApplication(sys.argv)
    auth_window = AuthWindow()
    auth_window.show() 
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()