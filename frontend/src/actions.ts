import { api } from './api'
export async function startScan(id:string, targets:string) {
  if (!window.confirm(`Start a new scan?\n\nAuthorized scope: ${targets}\n\nI confirm that I own or have explicit permission to assess every listed target, the IP addresses resolved from URL-only targets at launch, and any selected credential endpoint.`)) return null
  return api(`/scans/${id}/runs`,'POST',{authorized_scope_confirmed:true})
}
