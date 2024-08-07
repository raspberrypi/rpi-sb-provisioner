from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Container
from textual.widgets import Header, Footer, DataTable, Static, Button
from textual.reactive import reactive
from textual.message import Message
from textual.screen import Screen
from textual.widget import Widget
from textual import on
from textual import events
import systemctl_python


class Devices_list(Static):
    dev_type_g = ""
    devices=reactive([])

    def __init__(self, dev_type):
        self.dev_type = dev_type
        super().__init__()
    def update_devices(self) -> None:
        self.devices = systemctl_python.list_working_units("rpi-sb-" + self.dev_type + "*")
    def watch_devices(self, devices) -> None:
        """Called when the devices variable changes"""
        text = ""
        for i in range(len(devices)):
            text += devices[i] + "\n"
        self.styles.height = len(devices)
        self.update(text)

    def on_mount(self) -> None:
        self.set_interval(1/20, self.update_devices)

ROWS = [
    ("Serial Number",),
]

class CompletedDevicesList(Widget):
    dev_type_g = ""
    devices=reactive([])
    def compose(self) -> ComposeResult:
         yield DataTable()
    def __init__(self, dev_type):
        self.dev_type = dev_type
        super().__init__()
    def update_devices(self) -> None:
        self.devices = systemctl_python.list_completed_devices()
    def watch_devices(self, devices: list[str]) -> None:
        """Called when the devices variable changes"""
        table = self.query_one(DataTable)
        table_devices = []
        for device in self.devices:
            table_devices.append((device, ))
        table.clear()
        table.add_rows(table_devices)

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(*ROWS[0])
        table.add_rows(ROWS[1:])
        self.set_interval(1/20, self.update_devices)

class Failed_devices_list(Static):
    dev_type_g = ""
    devices=reactive([])
    def compose(self) -> ComposeResult:
         yield DataTable()
    def __init__(self, dev_type):
        self.dev_type = dev_type
        super().__init__()
    def update_devices(self) -> None:
        self.devices = systemctl_python.list_failed_devices()
    def watch_devices(self, devices: list[str]) -> None:
        """Called when the devices variable changes"""
        table = self.query_one(DataTable)
        table_devices = []# [("TEST",), ("TEST",)]
        for device in self.devices:
            table_devices.append((device, ))
        table.clear()
        table.add_rows(table_devices)

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns(*ROWS[0])
        table.add_rows(ROWS[1:])
        self.set_interval(1/20, self.update_devices)

class Triage_Box(Static):
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static("Triaging \n----------------"), Devices_list(dev_type="triage"))

class Keywrite_Box(Static):
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static("Keywriting \n----------------"), Devices_list(dev_type="keywriter"))

class Provision_Box(Static):
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static("Provisioning \n----------------"), Devices_list(dev_type="provision"))


class Completed_Box(Static):
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static("Completed \n----------------"), CompletedDevicesList(dev_type="provision"))

class Failed_Box(Static):
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static("Failed \n----------------"), Failed_devices_list(dev_type="provision"))

class Processing(Static):
    def compose(self) -> ComposeResult:
        yield Triage_Box("1", classes="box2")
        yield Keywrite_Box("2", classes="box2")
        yield Provision_Box("3", classes="box2")

class Ended(Static):
    def compose(self) -> ComposeResult:
        yield Completed_Box("1", classes="box2")
        yield Failed_Box("2", classes="box2")

class FileSelector(Container):
    def __init__(self, filelist):
        self.filelist = filelist
        self.selected_file = None
        self.id_to_filename = {}
        super().__init__()
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        # List files in the directory
        for file in self.filelist:
            self.id_to_filename.update([(file.replace(".", ""),  file)])
            yield Button(file, id=file.replace(".", ""), classes="fileselectorbutton")
    def get_filename_from_id(self, id) -> str:
        return self.id_to_filename[id]

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
            """Create child widgets for the app."""
            yield Header()
            yield Footer()
            yield Processing("Processing", classes="box")
            yield Ended("Completed", classes="box")
    def action_goto_log(self) -> None:
        self.dismiss(self.query_one(Ended).get_device())

    @on(DataTable.CellSelected)
    def on_cell_selected(self, event: DataTable.CellSelected) -> None:  
        self.dismiss(event.value)

class LogScreen(Screen):
    def __init__(self, device_name):
        self.device_name = device_name
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Footer()
        yield Static("This is the log screen for device: " + self.device_name, id="header_string")
        yield FileSelector(filelist=systemctl_python.list_device_files(self.device_name))
        yield ScrollableContainer(Static(" ", id="file_contents"))
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        static = self.query_one("#file_contents")
        fileselector = self.query_one("FileSelector")
        # Need to read the file into this container now!
        contents = systemctl_python.read_device_file(self.device_name, fileselector.get_filename_from_id(event.button.id))
        static.update(contents)

    def on_screen_resume(self) -> None:  
        static = self.query_one("#header_string")
        static.update(self.device_name)


class App(App):
    """A Textual app to manage stopwatches."""
    CSS_PATH = "layout.css"
    BINDINGS = [("m", "mainscreen", "Main Screen"), ("q", "quit", "Quit")]
    SCREENS = {"MainScreen": MainScreen(), "LogScreen": LogScreen("unknown-serial")}    

    def on_mount(self) -> None:
        self.title = "rpi-sb-provisioner"
        self.push_screen(LogScreen(device_name="INIT"))
        self.push_screen(MainScreen(), self.action_logscreen)

    def action_mainscreen(self):
        self.pop_screen()
        self.push_screen(MainScreen(), self.action_logscreen)

    def action_logscreen(self, device: str):
        self.push_screen(LogScreen(device))

if __name__ == "__main__":
    app = App()
    app.run()