/**
 * Checks if a single user permission entry matches the required permission.
 * Supports exact match and glob-style 'prefix.*' notation.
 *
 * @param {string} userPerm - e.g. 'admin.*' or 'users:read'
 * @param {string} required - e.g. 'admin.settings'
 * @returns {boolean}
 */
function matchPermission(userPerm, required) {
    if (userPerm === required) return true
    if (userPerm.endsWith('.*')) {
        const prefix = userPerm.slice(0, -2)
        return required === prefix || required.startsWith(prefix + '.')
    }
    return false
}

/**
 * Checks if a user has the required permission(s).
 * Supports:
 * - Exact match: 'users:read'
 * - Full wildcard '*': grants access to everything
 * - Namespace glob 'prefix.*': grants access to 'prefix' and 'prefix.*'
 *
 * @param {string[]} userPermissions - e.g. ['admin.*', 'users:read']
 * @param {string | string[]} required - e.g. 'admin.settings' or ['users:read', 'posts:write']
 * @returns {boolean}
 */
export function hasPermission(userPermissions, required) {
    if (!Array.isArray(userPermissions)) return false
    if (userPermissions.includes('*')) return true

    const requiredList = Array.isArray(required) ? required : [required]
    return requiredList.every((perm) => userPermissions.some((up) => matchPermission(up, perm)))
}

/**
 * Checks if a user has ANY of the required permissions.
 * Supports exact match, full wildcard '*', and namespace glob 'prefix.*'.
 *
 * @param {string[]} userPermissions
 * @param {string | string[]} required
 * @returns {boolean}
 */
export function hasAnyPermission(userPermissions, required) {
    if (!Array.isArray(userPermissions)) return false
    if (userPermissions.includes('*')) return true

    const requiredList = Array.isArray(required) ? required : [required]
    return requiredList.some((perm) => userPermissions.some((up) => matchPermission(up, perm)))
}
