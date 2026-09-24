import test from "node:test";
import assert from "node:assert/strict";
import { getTargetValidationError } from "./portValidation.js";

test("accepts valid IPv4 localhost input", () => {
  assert.equal(getTargetValidationError("127.0.0.1"), null);
  assert.equal(getTargetValidationError("localhost"), null);
});

test("rejects malformed IPv4 values with double dots", () => {
  const err = getTargetValidationError("127..0.1");
  assert.match(err, /127\.0\.0\.1|localhost/i);
});

test("rejects invalid characters", () => {
  const err = getTargetValidationError("bad host; rm -rf /");
  assert.match(err, /invalid characters|valid hostname|127\.0\.0\.1/i);
});
