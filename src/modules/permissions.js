/**
 * Checks if a user has the required permission(s).
 * Supports wildcard '*' as a permission that grants access to everything.
 *
 * @param {string[]} userPermissions - e.g. ['users:read', 'posts:write']
 * @param {string | string[]} required - e.g. 'users:read' or ['users:read', 'posts:write']
 * @returns {boolean}
 */
export function hasPermission(userPermissions, required) {
    if (!Array.isArray(userPermissions)) return false
    if (userPermissions.includes('*')) return true

    const requiredList = Array.isArray(required) ? required : [required]
    return requiredList.every((perm) => userPermissions.includes(perm))
}

/**
 * Checks if a user has ANY of the required permissions.
 * @param {string[]} userPermissions
 * @param {string | string[]} required
 * @returns {boolean}
 */
export function hasAnyPermission(userPermissions, required) {
    if (!Array.isArray(userPermissions)) return false
    if (userPermissions.includes('*')) return true

    const requiredList = Array.isArray(required) ? required : [required]
    return requiredList.some((perm) => userPermissions.includes(perm))
}
