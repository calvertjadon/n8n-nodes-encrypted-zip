"""Asserts the outcome of one smoke-lane workflow execution.

Usage: assert.py <expectation> <output-name|-> <n8n-exit-status>   (output on stdin)

`n8n execute --raw-output` prints its own startup lines before the execution
JSON, so the JSON is located first. Binary results are compared as bytes from
the file the workflow wrote through Write File: n8n's binary modes
(filesystem, s3, database) hide the bytes behind an id, so reading the CLI's
JSON would compare base64 of a mode marker instead.
"""

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / ".smoke-out"
SYNTHETIC_CONTENT = OUTPUT_DIR / "input" / "synthetic.bin"
CREDENTIALS = REPO_ROOT / "test" / "fixtures" / "smoke" / "credentials.json"


def execution(output: str) -> dict:
	"""The workflow execution record, without the CLI's startup and trailing lines."""
	start = re.search(r"^\{$", output, re.MULTILINE)
	if start is None:
		raise AssertionError(f"no execution JSON in the output:\n{output}")
	record, _ = json.JSONDecoder().raw_decode(output[start.start():])
	return record


def node_items(record: dict, node_name: str) -> list:
	run_data = record["data"]["resultData"]["runData"]
	if node_name not in run_data:
		raise AssertionError(f"node {node_name!r} did not run; ran: {sorted(run_data)}")
	return run_data[node_name][0]["data"]["main"][0]


def written_bytes(output_name: str) -> bytes:
	path = OUTPUT_DIR / output_name
	assert path.is_file(), f"the workflow did not write {path}"
	return path.read_bytes()


def expect_extracted_round_trip(record: dict, output_name: str, status: int, output: str) -> None:
	assert status == 0, f"n8n exited with {status}"
	items = node_items(record, "Extract")
	assert len(items) == 1, f"expected one extracted item, got {len(items)}"
	expected = SYNTHETIC_CONTENT.read_bytes()
	metadata = items[0]["json"]
	assert metadata.get("entryName") == "synthetic.bin", f"entry name was not reported: {metadata}"
	assert metadata.get("uncompressedSize") == len(expected), f"size mismatch: {metadata}"
	assert metadata.get("lastModified"), f"modified time was not reported: {metadata}"
	assert written_bytes(output_name) == expected, (
		"the extracted file does not match the synthetic content"
	)


def expect_wrong_password_error(record: dict, output_name: str, status: int, output: str) -> None:
	assert status != 0, "the workflow should have failed, but n8n exited with 0"
	error = record["data"]["resultData"].get("error")
	assert error, f"the workflow should have failed, but reported no error: {json.dumps(record)[:400]}"
	message = str(error.get("message", ""))
	assert "'ZIP Password'" in message and "does not open this archive" in message, (
		f"wrong-password copy missing from the execution error: {message!r}"
	)
	assert "[Item 0]" in message, f"the item index is missing from the error: {message!r}"
	for credential in json.loads(CREDENTIALS.read_text()):
		password = credential["data"]["password"]
		assert password not in output, f"the {credential['name']!r} password leaked into n8n's output"


EXPECTATIONS = {
	"extracted-round-trip": expect_extracted_round_trip,
	"wrong-password-error": expect_wrong_password_error,
}


def main() -> int:
	if len(sys.argv) != 4:
		print(__doc__, file=sys.stderr)
		return 2
	name, output_name, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
	expectation = EXPECTATIONS.get(name)
	if expectation is None:
		print(f"unknown expectation {name!r}; known: {', '.join(sorted(EXPECTATIONS))}", file=sys.stderr)
		return 2
	output = sys.stdin.read()
	try:
		record = execution(output)
		expectation(record, output_name, status, output)
	except (AssertionError, KeyError) as failure:
		print(f"FAIL ({name}): {failure}\n--- output ---\n{output}", file=sys.stderr)
		return 1
	print(f"PASS ({name})")
	return 0


if __name__ == "__main__":
	sys.exit(main())
