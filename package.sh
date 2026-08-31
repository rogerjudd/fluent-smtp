#!/bin/bash
# Build caz-sentry.zip, installable through Plugins -> Add New -> Upload.
set -e
cd "$(dirname "$0")"

php -l caz-sentry.php > /dev/null
php -l prepend.php > /dev/null
for f in includes/*.php; do php -l "$f" > /dev/null; done

php tests/harness.php      > /dev/null || { echo "Behaviour tests failed; not packaging."; exit 1; }
php tests/prepend-test.php > /dev/null || { echo "Prepend tests failed; not packaging."; exit 1; }

rm -f caz-sentry.zip
zip -rq caz-sentry.zip . \
    -x "caz-sentry.zip" -x "package.sh" -x "tests/*" -x "*.DS_Store"

echo "Built $(pwd)/caz-sentry.zip"
