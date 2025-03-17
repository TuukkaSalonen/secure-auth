const usernameRegex = '^[a-zA-Z0-9_]{3,32}$';

export const validateLoginInput = (username: string, password: string) => {
    if (!username || !password) {
        return { success: false, message: "Please fill in all fields."};
    }
    if (password.trim().length < 8 || password.trim().length > 64) {
        return { success: false, message: "Password must be between 8 and 64 characters without leading and trailing spaces."};
    }
    if (!username.match(usernameRegex)) {
        return { success: false, message: "Username must be between 3 and 32 characters and can only contain letters, numbers, and underscores."};
    }
    return { success: true, message: "Valid input."};
}

export const validateRegisterInput = (username: string, password: string, confirmPassword: string) => {
    if (!username || !password || !confirmPassword) {
        return { success: false, message: "Please fill in all fields."};
    }
    if (password.trim().length < 8 || password.trim().length > 64) {
        return { success: false, message: "Password must be between 8 and 64 characters without leading and trailing spaces."};
    }
    if (password !== confirmPassword) {
        return { success: false, message: "Passwords do not match."};
    }
    if (!username.match(usernameRegex)) {
        return { success: false, message: "Username must be between 3 and 32 characters and can only contain letters, numbers, and underscores."};
    }
    return { success: true, message: "Valid input."};
}