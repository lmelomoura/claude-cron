from security.fingerprint import fingerprint, secret_fingerprint


def test_reformatting_does_not_change_the_fingerprint():
    a = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + name")
    b = fingerprint("sast", "sql-injection", "app/db.py", "query   =  'SELECT ' + name  ")
    assert a == b


def test_a_real_change_does_change_it():
    a = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + name")
    b = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + other")
    assert a != b


def test_the_path_is_part_of_the_identity():
    a = fingerprint("sast", "sql-injection", "app/db.py", "x = 1")
    b = fingerprint("sast", "sql-injection", "app/web.py", "x = 1")
    assert a != b


def test_a_secret_fingerprint_never_contains_the_value():
    """The value is not an argument at all — it cannot leak through this door."""
    a = secret_fingerprint("aws_access_key", "config/prod.env")
    assert len(a) == 64


def test_a_secret_fingerprint_varies_with_the_path():
    a = secret_fingerprint("aws_access_key", "config/prod.env")
    b = secret_fingerprint("aws_access_key", "config/staging.env")
    assert a != b


def test_a_secret_fingerprint_is_stable_for_the_same_type_and_path():
    """No ordinal, no position: the same (type, path) always hashes the same,
    regardless of how many times it is called or what else is in the file."""
    a = secret_fingerprint("aws_access_key", "config/prod.env")
    b = secret_fingerprint("aws_access_key", "config/prod.env")
    assert a == b
