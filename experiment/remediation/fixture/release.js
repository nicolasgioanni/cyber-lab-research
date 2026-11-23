const { maxSatisfying } = require('semver');
const { createColors } = require('picocolors');

function selectRelease(publishedVersions, channelRange) {
  return maxSatisfying(publishedVersions, channelRange);
}

function formatSelection(channel, version, useColor = false) {
  const colors = createColors(useColor);
  const status = version === null ? colors.yellow('no matching release') : colors.green(version);
  return channel + ': ' + status;
}

module.exports = { selectRelease, formatSelection };
