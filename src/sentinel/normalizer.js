/**
 * Sentinel Security Layer: Resource Normalizer
 * Part of Vigil AI + Sentinel (Plan.pdf - Stage 2, Section 4.5)
 *
 * Implements canonical normalization for filesystem paths and network destinations.
 * Protects against path traversal, symlink escapes, TOCTOU races, and SSRF.
 */
'use strict';

const path = require('path');
const fs = require('fs');

// Prohibited sensitive system paths and directories
const SENSITIVE_SYSTEM_PREFIXES = [
  '/etc',
  '/var',
  '/proc',
  '/sys',
  '/dev',
  '/root',
  '/bin',
  '/sbin',
  '/usr/bin',
  '/usr/sbin'
];

const SENSITIVE_USER_FILES = [
  '.ssh',
  '.gnupg',
  '.aws',
  '.bashrc',
  '.zshrc',
  '.bash_profile',
  '.profile',
  '.gitconfig',
  '.netrc',
  'passwd',
  'shadow',
  'sudoers'
];

// Cloud metadata endpoints
const CLOUD_METADATA_HOSTS = [
  '169.254.169.254',
  'metadata.google.internal',
  'instance-data',
  'metadata.internal'
];

/**
 * Normalizes a filesystem path and verifies whether it safely resides within a designated workspace root.
 *
 * @param {string} targetPath - Path supplied by tool or model
 * @param {string} [workspaceRoot] - Designated allowed workspace directory
 * @returns {Object} { canonicalPath, isInsideWorkspace, isSensitiveSystemPath, error }
 */
function normalizeFilesystemPath(targetPath, workspaceRoot = process.cwd()) {
  if (!targetPath || typeof targetPath !== 'string') {
    return {
      canonicalPath: '',
      isInsideWorkspace: false,
      isSensitiveSystemPath: false,
      error: 'PATH_NULL_OR_EMPTY'
    };
  }

  // Strip zero-width obfuscation characters
  const cleanTargetPath = targetPath.replace(/[\u200B-\u200D\uFEFF]/g, '');

  // Null byte or control character injection check
  for (let i = 0; i < cleanTargetPath.length; i++) {
    const code = cleanTargetPath.charCodeAt(i);
    if (code <= 31 || code === 127) {
      return {
        canonicalPath: '',
        isInsideWorkspace: false,
        isSensitiveSystemPath: false,
        error: 'PATH_INJECTION_NULL_BYTE'
      };
    }
  }

  const cleanWorkspace = path.resolve(workspaceRoot);
  let resolvedTarget = path.resolve(cleanWorkspace, cleanTargetPath);

  // Symlink resolution
  try {
    if (fs.existsSync(resolvedTarget)) {
      resolvedTarget = fs.realpathSync(resolvedTarget);
    } else {
      // For paths that do not exist yet (e.g. write target), resolve nearest existing ancestor
      let ancestor = path.dirname(resolvedTarget);
      let relativeRemaining = path.basename(resolvedTarget);
      while (!fs.existsSync(ancestor) && ancestor !== path.dirname(ancestor)) {
        relativeRemaining = path.join(path.basename(ancestor), relativeRemaining);
        ancestor = path.dirname(ancestor);
      }
      if (fs.existsSync(ancestor)) {
        const canonicalAncestor = fs.realpathSync(ancestor);
        resolvedTarget = path.join(canonicalAncestor, relativeRemaining);
      }
    }
  } catch (err) {
    return {
      canonicalPath: resolvedTarget,
      isInsideWorkspace: false,
      isSensitiveSystemPath: false,
      error: 'REALPATH_RESOLUTION_FAILED: ' + err.message
    };
  }

  // Strict containment check: cleanWorkspace + separator
  const isInside = isPathContained(resolvedTarget, cleanWorkspace);

  // Check for sensitive OS locations
  const isSensitive = isSensitiveSystemLocation(resolvedTarget);

  return {
    canonicalPath: resolvedTarget,
    isInsideWorkspace: isInside,
    isSensitiveSystemPath: isSensitive,
    error: null
  };
}

/**
 * Helper: Strictly validates if target is inside root (prevents prefix attacks like /app vs /app-evil).
 */
function isPathContained(target, parent) {
  const rel = path.relative(parent, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Helper: Detects whether a path targets sensitive operating system or user secret directories.
 */
function isSensitiveSystemLocation(resolvedPath) {
  const norm = path.normalize(resolvedPath);
  for (const prefix of SENSITIVE_SYSTEM_PREFIXES) {
    if (norm === prefix || norm.startsWith(prefix + '/')) {
      return true;
    }
  }

  const parts = norm.split(path.sep);
  for (const sensitiveFile of SENSITIVE_USER_FILES) {
    if (parts.includes(sensitiveFile)) {
      return true;
    }
  }

  return false;
}

/**
 * Normalizes and classifies an outbound network destination.
 *
 * @param {string} destination - URL string or host[:port]
 * @returns {Object} { canonicalHost, port, isLoopback, isPrivateNetwork, isCloudMetadata, error }
 */
function normalizeNetworkDestination(destination) {
  if (!destination || typeof destination !== 'string') {
    return { canonicalHost: '', port: null, isLoopback: false, isPrivateNetwork: false, isCloudMetadata: false, error: 'DEST_NULL_OR_EMPTY' };
  }

  let host = '';
  let port = null;

  try {
    if (destination.includes('://')) {
      const parsed = new URL(destination);
      host = parsed.hostname.toLowerCase();
      port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    } else {
      const parts = destination.split(':');
      host = parts[0].toLowerCase();
      port = parts[1] ? parseInt(parts[1], 10) : 80;
    }
  } catch (err) {
    return { canonicalHost: '', port: null, isLoopback: false, isPrivateNetwork: false, isCloudMetadata: false, error: 'DEST_PARSE_FAILED' };
  }

  const isMetadata = CLOUD_METADATA_HOSTS.includes(host);
  const isLoop = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.startsWith('127.');
  const isPrivate = isLoop || isPrivateIp(host);

  return {
    canonicalHost: host,
    port,
    isLoopback: isLoop,
    isPrivateNetwork: isPrivate,
    isCloudMetadata: isMetadata,
    error: null
  };
}

/**
 * Detects private IPv4 subnets (RFC 1918) and link-local.
 */
function isPrivateIp(host) {
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  return false;
}

module.exports = {
  normalizeFilesystemPath,
  normalizeNetworkDestination,
  isPathContained,
  isSensitiveSystemLocation
};
