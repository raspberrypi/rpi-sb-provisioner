"""Customisation hooks: create, edit, enable, disable, delete.

"Enabled" is the owner-execute bit on the station's file, and an enabled
hook runs as root, so every step is checked on the station too.
"""
import unittest

from ui.harness.case import UITest

DIR = "/etc/rpi-sb-provisioner/scripts"
HOOK = "naked-provisioner-post-flash"
PATH = f"{DIR}/{HOOK}.sh"


class Hooks(UITest):
    def setUp(self):
        super().setUp()
        self.station.sh(f"rm -f {DIR}/*.sh")

    def mode(self):
        return self.station.sh(f"stat -c %a {PATH} 2>/dev/null || echo absent").strip()

    def card(self):
        return self.b.el(f".hook-card[data-filename='{HOOK}']")

    def status(self):
        return self.card().find_element("css selector", ".hook-status").text

    def open_tab(self):
        self.b.get("/customisation/list-scripts?activeTab=naked-provisioner")
        self.assertTrue(self.b.el("#naked-provisioner").is_displayed())

    def editor_value(self):
        return self.b.d.execute_script("return window.scriptEditor.getValue()")

    def save_in_editor(self, content):
        self.b.d.execute_script("window.scriptEditor.setValue(arguments[0])", content)
        self.b.click("#save-btn")
        self.b.settle()

    def put_hook(self, content, mode):
        self.station.put(PATH, content, mode)

    def test_lists_every_provisioner_and_stage(self):
        self.b.get("/customisation/list-scripts")
        self.assertClean()
        for prov, stages in {"fde-provisioner": 6, "idp-provisioner": 3,
                             "naked-provisioner": 6, "sb-provisioner": 6}.items():
            with self.subTest(prov=prov):
                self.assertEqual(stages, len(self.b.all(f"#{prov} .hook-card")))
        self.assertIn("Not set up", self.b.text())

    def test_tabs_switch_panels(self):
        self.b.get("/customisation/list-scripts")
        for prov in ("idp-provisioner", "sb-provisioner", "fde-provisioner"):
            with self.subTest(prov=prov):
                self.b.click(f"#{prov}-tab")
                self.assertTrue(self.b.el(f"#{prov}").is_displayed())
                self.assertEqual("true", self.b.el(f"#{prov}-tab").get_attribute("aria-selected"))

    def test_active_tab_survives_a_reload(self):
        self.open_tab()
        self.assertIn("active", self.b.el("#naked-provisioner-tab").get_attribute("class"))

    def test_create_opens_the_editor_without_writing_a_file(self):
        self.open_tab()
        self.card().find_element("css selector", "form button[type=submit]").click()
        self.b.settle()
        self.b.el("#editor")
        self.assertIn(HOOK, self.b.el("#script-filename").text)
        self.assertTrue(self.editor_value().strip(), "the editor should start from a template")
        self.assertEqual("absent", self.mode())
        self.assertClean()

    def test_saved_hook_is_created_disabled(self):
        self.b.get(f"/customisation/get-script?script={HOOK}")
        self.save_in_editor("#!/bin/sh\necho uitest\n")
        self.assertTrue(self.b.path().startswith("/customisation/list-scripts"))
        self.assertEqual("644", self.mode())
        self.assertEqual("#!/bin/sh\necho uitest\n", self.station.sh(f"cat {PATH}"))
        self.open_tab()
        self.assertEqual("Disabled", self.status())

    def test_edit_shows_and_replaces_the_contents(self):
        self.put_hook("#!/bin/sh\necho before\n", "0755")
        self.b.get(f"/customisation/get-script?script={HOOK}")
        self.assertIn("echo before", self.editor_value())
        self.save_in_editor("#!/bin/sh\necho after\n")
        self.assertIn("echo after", self.station.sh(f"cat {PATH}"))
        self.assertEqual("755", self.mode(), "saving must not change whether a hook is enabled")

    def test_enable_and_disable(self):
        self.put_hook("#!/bin/sh\n", "0644")
        self.open_tab()
        self.assertEqual("Disabled", self.status())
        self.card().find_element("css selector", "button.cust-btn-success").click()
        self.b.wait_text(f".hook-card[data-filename='{HOOK}'] .hook-status", "Enabled")
        self.assertEqual("755", self.mode())
        self.card().find_element("css selector", "button.cust-btn-warning").click()
        self.b.wait_text(f".hook-card[data-filename='{HOOK}'] .hook-status", "Disabled")
        self.assertEqual("644", self.mode())
        self.assertClean()

    def test_delete_asks_first(self):
        self.put_hook("#!/bin/sh\n", "0644")
        self.open_tab()
        self.b.d.execute_script("window.confirm = () => false;")
        self.card().find_element("css selector", "button.cust-btn-danger").click()
        self.b.settle()
        self.assertEqual("644", self.mode(), "cancelling must keep the hook")
        self.b.accept_confirm()
        self.card().find_element("css selector", "button.cust-btn-danger").click()
        self.b.wait_text(f".hook-card[data-filename='{HOOK}'] .hook-status", "Not set up")
        self.assertEqual("absent", self.mode())

    def test_status_follows_the_file_on_disk(self):
        self.put_hook("#!/bin/sh\n", "0755")
        self.open_tab()
        self.assertEqual("Enabled", self.status())

    def test_not_a_hook_point_is_refused(self):
        for name in ("naked-provisioner-no-such-stage", "../../etc/passwd", "x"):
            with self.subTest(name=name):
                self.b.get("/customisation/get-script?script=" + name)
                self.assertIn("not a valid hook point", self.b.text())
                self.assertClean(error_page=True)

    def test_hook_actions_need_a_hook_point(self):
        for action in ("enable-script", "disable-script", "delete-script"):
            with self.subTest(action=action):
                status, body = self.b.fetch(f"/customisation/{action}?script=not-a-hook", "POST")
                self.assertEqual(400, status, body)

    def test_only_hook_points_can_be_saved(self):
        for name in ("not-a-hook", "naked-provisioner-no-such-stage"):
            with self.subTest(name=name):
                status, body = self.b.fetch("/customisation/save-script", "POST",
                                            {"filename": name, "content": "#!/bin/sh\n"})
                self.assertEqual(400, status, body)
                self.assertEqual("", self.station.sh(f"ls {DIR}/{name}.sh 2>/dev/null || true").strip())

    def test_only_hook_points_can_be_uploaded(self):
        status, body = self.b.d.execute_async_script("""
            const done = arguments[0];
            const f = new FormData();
            f.append('script', new Blob(['#!/bin/sh\\n']), 'not-a-hook.sh');
            fetch('/customisation/upload-script', {method: 'POST', body: f})
              .then(r => r.text().then(t => done([r.status, t])), e => done([0, String(e)]));
        """)
        self.assertEqual(400, status, body)
        self.assertEqual("", self.station.sh(f"ls {DIR}/not-a-hook.sh 2>/dev/null || true").strip())

    def test_upload_of_a_hook_point_is_written(self):
        status, body = self.b.d.execute_async_script("""
            const [name, done] = arguments;
            const f = new FormData();
            f.append('script', new Blob(['#!/bin/sh\\necho uploaded\\n']), name + '.sh');
            fetch('/customisation/upload-script', {method: 'POST', body: f})
              .then(r => r.text().then(t => done([r.status, t])), e => done([0, String(e)]));
        """, HOOK)
        self.assertEqual(200, status, body)
        self.assertIn("echo uploaded", self.station.sh(f"cat {PATH}"))

    def test_editor_is_ace_from_this_station(self):
        self.b.get(f"/customisation/get-script?script={HOOK}")
        self.assertTrue(self.b.el("#ace-editor").is_displayed(), "Ace should replace the textarea")
        self.assertFalse(self.b.el("textarea#editor").is_displayed())
        self.assertTrue(self.b.d.execute_script("return !!(window.ace && ace.version)"))
        self.assertClean()

    def test_editor_works_without_ace(self):
        # Ace missing or broken: the textarea is the editor, and saving works.
        self.b.d.execute_cdp_cmd("Network.enable", {})
        self.b.d.execute_cdp_cmd("Network.setBlockedURLs", {"urls": ["*/static/js/ace/*"]})
        try:
            self.b.get(f"/customisation/get-script?script={HOOK}")
            self.b.drain_console()
            area = self.b.el("textarea#editor")
            self.assertTrue(area.is_displayed())
            area.clear()
            area.send_keys("#!/bin/sh\necho plain\n")
            self.b.click("#save-btn")
            self.b.settle()
            self.assertIn("echo plain", self.station.sh(f"cat {PATH}"))
        finally:
            self.b.d.execute_cdp_cmd("Network.setBlockedURLs", {"urls": []})

    def test_help_opens_and_closes(self):
        self.b.get(f"/customisation/get-script?script={HOOK}")
        self.b.click("#script-help-btn")
        self.assertTrue(self.b.visible("#helpModal").is_displayed())
        self.b.click("#helpModal .close")
        self.b.settle()
        self.assertFalse(self.b.el("#helpModal").is_displayed())

    def test_copy_from_another_provisioner(self):
        self.station.put(f"{DIR}/sb-provisioner-post-flash.sh", "#!/bin/sh\necho from-sb\n", "0644")
        self.b.get(f"/customisation/get-script?script={HOOK}")
        self.b.click("#copy-from-btn")
        self.b.accept_confirm()
        self.b.click("a.copy-from-item[data-provisioner='sb-provisioner']")
        self.b.settle()
        self.assertIn("echo from-sb", self.editor_value())
        self.assertEqual("absent", self.mode(), "copying fills the editor; it must not save")

    def test_back_link_returns_to_the_tab(self):
        self.b.get(f"/customisation/get-script?script={HOOK}&activeTab=naked-provisioner")
        self.b.click("a[href*='/customisation/list-scripts']")
        self.b.settle()
        self.assertTrue(self.b.el("#naked-provisioner").is_displayed())
