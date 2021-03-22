# Changelog

## next (minor)

- Don't apply jitter to delays.
- Add `--watch-delay` option.
- Add `--watch-immediately` option.
- Wait until the first announce is sent before starting the competing announce watcher.

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
