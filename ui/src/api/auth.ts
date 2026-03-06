import { get, post } from './client'
import type { User } from '../types'

export function login(username: string, password: string): Promise<{ token: string }> {
  return post('/auth/local/login', { username, password })
}

export function logout(): Promise<{ message: string }> {
  return post('/auth/local/logout')
}

export function me(): Promise<User> {
  return get('/me')
}
