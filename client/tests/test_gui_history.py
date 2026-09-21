from knockc.gui import load_history, remember, save_history


def test_missing_file_returns_empty_lists(tmp_path):
    assert load_history(tmp_path / "does-not-exist.json") == {"config": [], "target": []}


def test_corrupt_file_returns_empty_lists(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("not valid json")
    assert load_history(path) == {"config": [], "target": []}


def test_save_then_load_round_trips(tmp_path):
    path = tmp_path / "nested" / "history.json"
    history = {"config": ["/a/knock.conf"], "target": ["203.0.113.10"]}
    save_history(history, path)
    assert load_history(path) == history


def test_remember_moves_existing_entry_to_front_without_duplicating():
    history = {"config": ["a", "b", "c"], "target": []}
    remember(history, "config", "b")
    assert history["config"] == ["b", "a", "c"]


def test_remember_adds_new_entry_to_front():
    history = {"config": ["a"], "target": []}
    remember(history, "config", "z")
    assert history["config"] == ["z", "a"]


def test_remember_ignores_empty_value():
    history = {"config": ["a"], "target": []}
    remember(history, "config", "")
    assert history["config"] == ["a"]


def test_remember_caps_at_max_recents():
    history = {"config": [str(i) for i in range(10)], "target": []}
    remember(history, "config", "new")
    assert len(history["config"]) == 10
    assert history["config"][0] == "new"
    assert "9" not in history["config"]
