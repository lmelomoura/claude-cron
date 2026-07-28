"""Editing the one operator profile.

The avatar is what makes this worth its own file: it is stored inline in the
operator row as a data: URI, so the column is a place where a browser-executable
string could end up being handed straight back to the page. What the server
accepts there is the whole defence — the page downscales and re-encodes before
uploading, but a limit only the client keeps is not a limit.
"""

import pytest

PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="


@pytest.fixture
def profile(srv):
    """A fresh operator, whatever earlier tests did to the one before."""
    conn = srv.app_conn()
    conn.execute("DELETE FROM operator")
    conn.commit()
    conn.close()
    code, _ = srv.create_operator("Ada Lovelace", "ada@example.org", "abcdefgh", "abcdefgh")
    assert code == 200
    return srv


def test_name_and_email_are_saved(profile):
    code, payload = profile.update_operator("Ada Byron", "ada@byron.org",
                                            None, "", "", "")
    assert code == 200, payload
    assert payload["user"]["name"] == "Ada Byron"
    assert payload["user"]["email"] == "ada@byron.org"


def test_an_untouched_photo_survives_an_unrelated_save(profile):
    """`avatar` absent must mean "leave it alone", not "clear it" — otherwise
    correcting a typo in your name silently deletes your photo."""
    profile.update_operator("Ada", "ada@example.org", PNG, "", "", "")
    code, payload = profile.update_operator("Ada Byron", "ada@example.org",
                                            None, "", "", "")
    assert code == 200
    assert payload["user"]["avatar"] == PNG, "the photo was dropped by a name change"


def test_an_empty_photo_clears_it(profile):
    profile.update_operator("Ada", "ada@example.org", PNG, "", "", "")
    _, payload = profile.update_operator("Ada", "ada@example.org", "", "", "", "")
    assert payload["user"]["avatar"] == ""


@pytest.mark.parametrize("avatar", [
    "javascript:alert(1)",
    "https://example.org/face.png",
    "data:text/html;base64,PHNjcmlwdD4=",
    # SVG is an image the <img> tag would render and a document that can carry a
    # <script>. Raster only, so the column cannot hold anything executable.
    "data:image/svg+xml;base64,PHN2Zz48c2NyaXB0Pjwvc2NyaXB0Pjwvc3ZnPg==",
])
def test_only_inline_raster_images_are_accepted(profile, avatar):
    code, payload = profile.update_operator("Ada", "ada@example.org", avatar, "", "", "")
    assert code == 400, f"{avatar!r} was accepted"
    assert "inline image" in payload["error"]


def test_an_oversized_photo_is_refused(profile):
    big = "data:image/png;base64," + "A" * (profile.AVATAR_MAX_BYTES + 1)
    code, payload = profile.update_operator("Ada", "ada@example.org", big, "", "", "")
    assert code == 400
    assert "too large" in payload["error"]


def test_changing_the_password_needs_the_current_one(profile):
    """A signed-in tab is not proof of who is at the keyboard, and this password
    cannot be recovered from anywhere — so the old one is the only check there is."""
    code, payload = profile.update_operator("Ada", "ada@example.org", None,
                                            "wrong-one", "newpassword", "newpassword")
    assert code == 403
    assert "current password" in payload["error"]
    # ...and the old password must still work afterwards.
    row = profile._operator_row()
    assert profile.verify_password("abcdefgh", row["password"])


def test_a_correct_current_password_changes_it(profile):
    code, _ = profile.update_operator("Ada", "ada@example.org", None,
                                      "abcdefgh", "newpassword", "newpassword")
    assert code == 200
    row = profile._operator_row()
    assert profile.verify_password("newpassword", row["password"])
    assert not profile.verify_password("abcdefgh", row["password"])


def test_an_empty_password_leaves_it_alone(profile):
    """The three password boxes are optional: saving a new email must not need
    them, and must not disturb the password."""
    code, _ = profile.update_operator("Ada", "new@example.org", None, "", "", "")
    assert code == 200
    assert profile.verify_password("abcdefgh", profile._operator_row()["password"])


def test_a_bad_email_is_refused(profile):
    code, payload = profile.update_operator("Ada", "not-an-email", None, "", "", "")
    assert code == 400
    assert "email" in payload["error"]


def test_the_reload_stamp_moves_when_the_photo_changes(profile):
    """The stamp is what tells other tabs their copy of the page is stale. The
    avatar is part of the profile, so changing it has to move it."""
    before = profile.operator_stamp()
    profile.update_operator("Ada", "ada@example.org", PNG, "", "", "")
    assert profile.operator_stamp() != before
