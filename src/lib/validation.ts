import { z } from 'zod'
import { sanitizeInput } from './security'

const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/
const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,20}$/

export const loginSchema = z.object({
  email: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().email()),
  password: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().min(8).max(128).regex(PASSWORD_REGEX, 'Password must contain letters, numbers and symbols'))
})

export const registerSchema = z
  .object({
    username: z
      .string()
      .transform(val => sanitizeInput(val))
      .pipe(z.string().min(3).max(20).regex(USERNAME_REGEX, 'Username can only contain letters, numbers, underscores and hyphens')),
    email: z
      .string()
      .transform(val => sanitizeInput(val))
      .pipe(z.string().email()),
    password: z
      .string()
      .transform(val => sanitizeInput(val))
      .pipe(z.string().min(8).max(128).regex(PASSWORD_REGEX, 'Password must contain letters, numbers and symbols')),
    confirmPassword: z
      .string()
      .transform(val => sanitizeInput(val))
      .pipe(z.string().min(8).max(128).regex(PASSWORD_REGEX, 'Password must contain letters, numbers and symbols'))
  })
  .refine(data => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword']
  })

export const profileUpdateSchema = z.object({
  username: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().min(3).max(20).regex(USERNAME_REGEX, 'Invalid username'))
    .optional(),
  email: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().email())
    .optional(),
  bio: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().max(300))
    .optional(),
  avatar: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().url())
    .optional(),
  displayName: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().max(50))
    .optional()
})

export const commentSchema = z.object({
  content: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().min(1).max(1000))
})

export const searchSchema = z.object({
  query: z
    .string()
    .transform(val => sanitizeInput(val))
    .pipe(z.string().max(100))
})

export type LoginCredentials = z.infer<typeof loginSchema>
export type RegisterCredentials = z.infer<typeof registerSchema>
export type ProfileUpdate = z.infer<typeof profileUpdateSchema>
export type CommentInput = z.infer<typeof commentSchema>
export type SearchQuery = z.infer<typeof searchSchema>
