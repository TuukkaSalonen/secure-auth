import * as yup from "yup";

const usernameRegex = /^[a-zA-Z0-9_]{3,32}$/;
const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)[A-Za-z\d]{8,64}$/;

const loginSchema = yup.object().shape({
  username: yup
    .string()
    .matches(
      usernameRegex,
      "Username must be between 3 and 32 characters and can only contain letters, numbers, and underscores."
    )
    .required("Username is required."),
  password: yup
    .string()
    .matches(
      passwordRegex,
      "Password must be between 8 and 64 characters and contain at least one uppercase letter, one lowercase letter, and one number."
    )
    .required("Password is required."),
});

const registerSchema = yup.object().shape({
  username: yup
    .string()
    .matches(
      usernameRegex,
      "Username must be between 3 and 32 characters and can only contain letters, numbers, and underscores."
    )
    .required("Username is required."),
  password: yup
    .string()
    .matches(
      passwordRegex,
      "Password must be between 8 and 64 characters and contain at least one uppercase letter, one lowercase letter, and one number."
    )
    .required("Password is required."),
  confirmPassword: yup
    .string()
    .oneOf([yup.ref("password"), undefined], "Passwords must match.")
    .required("Confirm password is required."),
});

// Validate login input
export const validateLoginInput = async (
  username: string,
  password: string
) => {
  if (!username || !password) {
    return { success: false, message: "Please fill in all fields." };
  }
  try {
    await loginSchema.validate({ username, password });
    return { success: true, message: "Valid input." };
  } catch (err) {
    return { success: false, message: (err as yup.ValidationError).errors[0] };
  }
};

// Validate register input
export const validateRegisterInput = async (
  username: string,
  password: string,
  confirmPassword: string
) => {
  if (!username || !password || !confirmPassword) {
    return { success: false, message: "Please fill in all fields." };
  }
  try {
    await registerSchema.validate({ username, password, confirmPassword });
  } catch (err) {
    return { success: false, message: (err as yup.ValidationError).errors[0] };
  }
  return { success: true, message: "Valid input." };
};
