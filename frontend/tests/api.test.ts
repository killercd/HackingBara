import { describe, it, expect, vi, afterEach } from 'vitest'
import { api, csrfToken, lines } from '../src/api'

afterEach(()=>vi.unstubAllGlobals())
describe('typed API boundary',()=>{
  it('extracts exactly the CSRF cookie',()=>{
    expect(csrfToken('other=secret; hb_csrf=abc%2B123; end=x')).toBe('abc+123')
    expect(csrfToken('other=secret')).toBe('')
  })
  it('normalizes multiline target input without inventing entries',()=>{
    expect(lines(' 192.0.2.1 \r\n\n2001:db8::1\n')).toEqual(['192.0.2.1','2001:db8::1'])
  })
  it('sends CSRF and same-origin cookies on mutations',async()=>{
    vi.stubGlobal('document',{cookie:'hb_csrf=token'})
    const fetch=vi.fn().mockResolvedValue(new Response(JSON.stringify({id:'new'}),{status:201}))
    vi.stubGlobal('fetch',fetch)
    expect(await api('/scans','POST',{name:'Lab'})).toEqual({id:'new'})
    expect(fetch.mock.calls[0][1]).toMatchObject({method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':'token'},body:'{"name":"Lab"}'})
  })
  it('shows validation details and handles empty success responses',async()=>{
    vi.stubGlobal('document',{cookie:''})
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({error:{message:'Validation failed',details:[{field:'body.targets',message:'Invalid target'}]}}),{status:422})))
    await expect(api('/scans','POST',{})).rejects.toThrow('body.targets: Invalid target')
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(null,{status:204})))
    expect(await api('/auth/logout','POST')).toBeNull()
  })
})
