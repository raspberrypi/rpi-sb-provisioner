from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Container
from textual.widgets import Header, Footer, DataTable, Static, Button, Input
from textual.reactive import reactive
from textual.message import Message
from textual.screen import Screen
from textual.widget import Widget
from textual import on
from textual import events
import systemctl_python

class ParamWidget(Widget):
    def __init__(self, paramname, paramvalue, currentval):
        self.paramname = paramname
        self.paramvalue = paramvalue
        self.currentval = currentval
        super().__init__()
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Static(self.paramname, classes="paramname")
        yield Input(placeholder=self.paramvalue, classes="paramentry", value=self.currentval)
        yield Button("Help!", classes="paramhelp")

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
            """Create child widgets for the app."""
            yield Header()
            yield Footer()
            for param in defaultparams:
                yield ParamWidget(paramname=param, paramvalue=defaultparams[param], currentval=initialparams[param])
    
    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:  
        ## Add handler here!


class App(App):
    """A Textual app to manage stopwatches."""
    CSS_PATH = "config_app.css"
    BINDINGS = [("m", "mainscreen", "Main Screen"), ("q", "quit", "Quit")]
    SCREENS = {"MainScreen": MainScreen()}    

    def on_mount(self) -> None:
        self.title = "rpi-sb-provisioner config editor"
        self.push_screen(MainScreen())

    def action_mainscreen(self):
        self.pop_screen()
        self.push_screen(MainScreen())


### initially need to open the default config files
defaultparams = {}
f = open("/etc/default/rpi-sb-provisioner")
contents_by_line = f.read().split("\n")
for line in contents_by_line:
    if len(line.split("=")) > 1:
        defaultparams.update([(line.split("=")[0], line.split("=")[1])])
    else:
        defaultparams.update([(line.split("=")[0], "")])

initialparams = {}
f = open("/etc/rpi-sb-provisioner/config")
contents_by_line = f.read().split("\n")
for line in contents_by_line:
    if len(line.split("=")) > 1:
        initialparams.update([(line.split("=")[0], line.split("=")[1])])
    else:
        initialparams.update([(line.split("=")[0], "")])
initialparams.pop("")
defaultparams.pop("")
print(initialparams)
print(defaultparams)

### Find the differences!
different_from_defaults = []
for param in defaultparams:
    if initialparams[param] != defaultparams[param]:
        different_from_defaults.append(param)

### Load helper descriptor!
helper = {}
f = open("config_app_helper.json")
contents_by_param = f.read().split("\n")
for line in contents_by_param:
    if len(line.split("|")) > 1:
        helper.update([(line.split("|")[0], line.split("|")[1])])
    else:
        print("Error - unable to correctly parse helper line: " + line)
helper.pop("")

if __name__ == "__main__":
    app = App()
    app.run()