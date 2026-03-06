import { get, post } from './client'
import type { PreviewResult, DeploymentSnapshot, DeploymentDiff } from '../types'

export function previewZone(zoneId: number): Promise<PreviewResult> {
  return post(`/zones/${zoneId}/preview`)
}

export function pushZone(
  zoneId: number,
  purgeDrift = false,
): Promise<{ message: string }> {
  return post(`/zones/${zoneId}/push`, { purge_drift: purgeDrift })
}

export function listDeployments(
  zoneId: number,
  limit = 50,
): Promise<DeploymentSnapshot[]> {
  return get(`/zones/${zoneId}/deployments?limit=${limit}`)
}

export function getDeployment(
  zoneId: number,
  deploymentId: number,
): Promise<DeploymentSnapshot> {
  return get(`/zones/${zoneId}/deployments/${deploymentId}`)
}

export function getDeploymentDiff(
  zoneId: number,
  deploymentId: number,
): Promise<DeploymentDiff> {
  return get(`/zones/${zoneId}/deployments/${deploymentId}/diff`)
}

export function rollback(
  zoneId: number,
  deploymentId: number,
  cherryPickIds?: number[],
): Promise<{ message: string }> {
  return post(`/zones/${zoneId}/deployments/${deploymentId}/rollback`, cherryPickIds ? { cherry_pick_ids: cherryPickIds } : {})
}
