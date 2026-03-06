import type { ApiError } from '../types'

const BASE_URL = '/api/v1'

export class ApiRequestError extends Error {
  status: number
  body: ApiError

  constructor(status: number, body: ApiError) {
    super(body.message)
    this.name = 'ApiRequestError'
    this.status = status
    this.body = body
  }
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('jwt')
  if (token) {
    return { Authorization: `Bearer ${token}` }
  }
  return {}
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`
  const headers: Record<string, string> = {
    ...getAuthHeaders(),
    ...(options.headers as Record<string, string>),
  }

  if (options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(url, {
    ...options,
    headers,
  })

  if (response.status === 401) {
    localStorage.removeItem('jwt')
    window.location.href = '/login'
    throw new ApiRequestError(401, { error: 'unauthorized', message: 'Session expired' })
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({
      error: 'unknown',
      message: response.statusText,
    }))
    throw new ApiRequestError(response.status, body)
  }

  if (response.status === 204 || response.headers.get('content-length') === '0') {
    return undefined as T
  }

  return response.json()
}

export function get<T>(path: string): Promise<T> {
  return apiRequest<T>(path)
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return apiRequest<T>(path, {
    method: 'POST',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

export function put<T>(path: string, body: unknown): Promise<T> {
  return apiRequest<T>(path, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
}

export function del<T>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: 'DELETE' })
}
