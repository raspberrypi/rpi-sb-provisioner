from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Container
from textual.widgets import Header, Footer, DataTable, Static, Button, Input
from textual.reactive import reactive
from textual.message import Message
from textual.screen import Screen, ModalScreen
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
        yield Button("Help!", classes="paramhelp", id=self.paramname + "_helpbutton")

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
            """Create child widgets for the app."""
            yield Header()
            yield Footer()
            for param in defaultparams:
                yield ParamWidget(paramname=param, paramvalue=defaultparams[param], currentval=initialparams[param])


class HelpScreen(Screen):
    def __init__(self, paramname, defaultvalue, currentvalue, optional, helptext):
        self.paramname = paramname
        self.defaultvalue = defaultvalue
        self.currentvalue = currentvalue
        self.optional = optional
        self.helptext = helptext
        if self.defaultvalue == "":
            self.defaultvalue = "None"
        super().__init__()
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Container(Static(self.paramname + "\n"), Static(self.optional + "\n"), Static(self.helptext + "\n"), Static("Default Value: " + self.defaultvalue + "\n"), Button("OK", id="close_help_screen"), id="dialog")



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
    
    @on(Button.Pressed)
    def on_button_pressed(self, event: Button.Pressed) -> None:  
        if "helpbutton" in event.button.id:
            paramname = event.button.id.replace("_helpbutton", "")
            self.push_screen(HelpScreen(paramname, defaultparams[paramname], "idk", required[paramname], helper[paramname]))
        if "close_help_screen" in event.button.id: 
            self.pop_screen()

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
required = {}
f = open("config_app.helper")
contents_by_param = f.read().split("\n")
for line in contents_by_param:
    if len(line.split("|")) > 1:
        helper.update([(line.split("|")[0], line.split("|")[2])])
        required.update([(line.split("|")[0], line.split("|")[1])])
    else:
        print("Error - unable to correctly parse helper line: " + line)
print(helper)
print(required)
if __name__ == "__main__":
    app = App()
    app.run()