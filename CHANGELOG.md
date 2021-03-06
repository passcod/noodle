# Changelog

## v1.1.1 (2021-03-22)

- Fix bug where watcher would always start immediately if `--count` wasn't provided.

## v1.1.0 (2021-03-22)

- Don't apply jitter to delays.
- Add `--watch-delay` option.
- Add `--watch-immediately` option.
- Wait until the first announce is sent before starting the competing announce watcher.
- Don't crash if the IP exists on the interface already.
- Add `--die-if-ip-exists`.
- Add `--remove-pre-existing-ip`.
- Add warning if a /32 is used.

## v1.0.1 (2021-03-21)

- Handle runtime (as opposed to startup time) errors with logging rather than eyre.
- Remove readme mention of error code 17 (was never true).
- Actually exit with code 1 after a runtime error (was 0).
- Retire debug mode pretty logger.
- Omit other modules from logs except at trace level.
- Add module path to logs at trace level.
- Use string level instead of bunyan integer level.
- Add timestamps to logs.

## v1.0.0 (2021-03-20)

Initial release
