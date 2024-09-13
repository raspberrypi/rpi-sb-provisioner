import os

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Header, Footer, Static, Button, Input
from textual.screen import Screen
from textual.widget import Widget
from textual import on

import validator


class ParamWidget(Widget):
    def __init__(self, paramname, paramvalue, currentval):
        self.paramname = paramname
        self.paramvalue = paramvalue
        self.currentval = currentval
        super().__init__()
    def compose(self) -> ComposeResult:
        yield Static(self.paramname, classes="paramname", id="nameentry_" + self.paramname)
        yield Input(placeholder=self.paramvalue, classes="paramentry", value=self.currentval, id="param_entry_"+self.paramname)   #, validate_on="blur", validators=[validate(self.paramname)])
        yield Button("Help!", classes="paramhelp", id=self.paramname + "_helpbutton")

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()
            for param in defaultparams:
                yield ParamWidget(paramname=param, paramvalue=defaultparams[param], currentval=initialparams[param])
            yield Container(Button("Write verified params to config file", id="write_button", classes="write_button"), classes="bottom_bar")

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
        yield Container(Static(self.paramname + "\n"), Static(self.optional + "\n"), Static(self.helptext + "\n"), Static("Default Value: " + self.defaultvalue + "\n"), Button("OK", id="close_help_screen"), id="dialog")


class ValidatedScreen(Screen):
    def __init__(self, paramname, errmsg, defaultvalue, currentvalue, optional, helptext):
        self.paramname = paramname
        self.defaultvalue = defaultvalue
        self.currentvalue = currentvalue
        self.optional = optional
        self.helptext = helptext
        self.errmsg = errmsg
        if self.defaultvalue == "":
            self.defaultvalue = "None"
        super().__init__()
    def compose(self) -> ComposeResult:
        yield Container(Static("ERROR VALIDATING: " + self.paramname + " - NOT WRITING!" + "\n"),
                        Static("Error is : " + self.errmsg + "\n"),
                        Static("This value is " + self.optional + "\n"),
                        Static(self.helptext + "\n"),
                        Static("Default Value: " + self.defaultvalue + "\n"),
                        Button("OK", id="close_help_screen"),
                        id="dialog")


class OpeningScreen(Screen):
    def __init__(self, differed_params, mandatory_not_set):
        self.differed_params = ""
        self.mandatory_not_set = ""
        if len(differed_params) != 0:
            for param in differed_params:
                self.differed_params += param + " "
        if len(mandatory_not_set) != 0:
            for param in mandatory_not_set:
                self.mandatory_not_set += param + " "
        super().__init__()
    def compose(self) -> ComposeResult:
        if self.differed_params == "":
            warning_text_1 = ""
        else:
            warning_text_1 = "WARNING - The parameters: " + self.differed_params + "vary from that suggested in the defaults file!\n"
        
        if self.mandatory_not_set == "":
            warning_text_2 = ""
        else:
            warning_text_2 = "WARNING - The Mandatory values: " + self.mandatory_not_set + "have also not been set and will need to be set for provisioner to run!\n"
        
        yield Container(Static(warning_text_1),
                        Static(warning_text_2),
                        Button("OK", id="close_help_screen2"),
                        id="dialog2")



class App(App):
    CSS_PATH = "config_app.css"
    BINDINGS = [("q", "quit", "Quit")]
    SCREENS = {"MainScreen": MainScreen()}    

    def on_mount(self) -> None:
        self.title = "rpi-sb-provisioner config editor"
        self.push_screen(MainScreen())
        if (len(different_from_defaults) > 0) or (len(mandatory_not_set) > 0):
            self.push_screen(OpeningScreen(different_from_defaults, mandatory_not_set))

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
        if "write_button" in event.button.id:
            f = open("/etc/rpi-sb-provisioner/config", "w+")
            for param in params_to_save:
                if param != "":
                    f.write(param + "=" + params_to_save[param] + "\n")
            f.close()
            quit()

    @on(Input.Submitted)
    def on_input_submitted(self, event: Input.Submitted) -> None:  
        if "param_entry" in event.input.id:
            paramname = event.input.id.replace("param_entry_", "")
            validate = getattr(validator, "validate_" + paramname)
            success, errmsg = validate(event.input.value)
            if not(success):
                inputbox = self.query_one("#param_entry_" + paramname)
                inputbox.classes = "paramentry"
                nametext = self.query_one("#nameentry_" + paramname)
                nametext.update("╳ - " + paramname)
                self.push_screen(ValidatedScreen(paramname, errmsg, defaultparams[paramname], "idk", required[paramname], helper[paramname]))
            if success:
                inputbox = self.query_one("#param_entry_" + paramname)
                inputbox.classes = "success_entry"
                params_to_save[paramname] = event.input.value
                nametext = self.query_one("#nameentry_" + paramname)
                nametext.update("✓ - " + paramname)





### initially need to open the default config files
defaultparams = {}
initialparams = {}
params_to_save = {}
f = open("/etc/default/rpi-sb-provisioner", "r")
contents_by_line = f.read().split("\n")
for line in contents_by_line:
    if len(line.split("=")) > 1:
        defaultparams.update([(line.split("=")[0], line.split("=")[1])])
        initialparams.update([(line.split("=")[0], line.split("=")[1])])
        params_to_save.update([(line.split("=")[0], line.split("=")[1])])
    else:
        defaultparams.update([(line.split("=")[0], "")])
        params_to_save.update([(line.split("=")[0], "")])
        initialparams.update([(line.split("=")[0], "")])

if os.path.exists("/etc/rpi-sb-provisioner/config"):
    f = open("/etc/rpi-sb-provisioner/config", "r")
    contents_by_line = f.read().split("\n")
    for line in contents_by_line:
        if len(line.split("=")) > 1:
            initialparams.update([(line.split("=")[0], line.split("=")[1])])
            params_to_save[line.split("=")[0]] = line.split("=")[1]
        else:
            initialparams.update([(line.split("=")[0], "")])
    try:
        initialparams.pop("")
        defaultparams.pop("")
    except:
        pass

### Find the differences!
different_from_defaults = []
for param in defaultparams:
    if defaultparams[param] != "":
        if param in initialparams:
            if initialparams[param] != defaultparams[param]:
                different_from_defaults.append(param)
        else:
            different_from_defaults.append(param)

### Load helper descriptor!
helper = {}
required = {}
mandatory_not_set = []
f = open("config_app.helper")
contents_by_param = f.read().split("\n")
for line in contents_by_param:
    if len(line.split("|")) > 1:
        helper.update([(line.split("|")[0], line.split("|")[2])])
        required.update([(line.split("|")[0], line.split("|")[1])])
        if "Mandatory" in required[line.split("|")[0]]:
            if params_to_save[line.split("|")[0]] == "":
                mandatory_not_set.append(line.split("|")[0])
    else:
        print("Error - unable to correctly parse helper line: " + line)

if __name__ == "__main__":
    app = App()
    app.run()