from form_discovery import discover_html


def test_multiline_single_quote_multipart_form_and_inputs() -> None:
    html = """
    <form
      action='notices.php?mode=write'
      method='post'
      enctype='multipart/form-data'>
      <input type='hidden' name='csrf' value='token'>
      <input type='text' name='title' value='hello'>
      <textarea name='content'>body</textarea>
      <input type='file' name='attachment'>
      <select name='department'><option value='sales'>Sales</option></select>
      <button type='submit'>Save</button>
    </form>
    """
    links, forms = discover_html(html, "http://192.168.1.10/REDRED/notices.php")
    assert not links
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "http://192.168.1.10/REDRED/notices.php?mode=write"
    assert form.method == "POST"
    assert form.enctype == "multipart/form-data"
    assert [(item.name, item.input_type) for item in form.inputs] == [
        ("csrf", "hidden"), ("title", "text"), ("content", "textarea"),
        ("attachment", "file"), ("department", "select"),
    ]
