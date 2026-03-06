import { get } from './client'

export interface HealthResponse {
  status: string
}

export function getHealth(): Promise<HealthResponse> {
  return get('/health')
}
