import { test, expect } from '@playwright/test'

test('Subdomain mode imports a list, saves it and shows DNS results', async ({page}) => {
  let saved: Record<string, any> | undefined
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    let json: unknown = {items: [], total: 0, total_pages: 0}
    if(path.endsWith('/auth/me')) json = {username: 'operator'}
    else if(path.endsWith('/scans') && route.request().method() === 'POST') {
      const contentType = route.request().headers()['content-type']
      expect(contentType).toContain('multipart/form-data; boundary=')
      const requestBody = route.request().postData()!
      const config = JSON.parse(requestBody.match(/name="config"\r\n\r\n([\s\S]*?)\r\n--/)![1])
      expect(config).not.toHaveProperty('subdomains')
      expect(requestBody).toContain('name="wordlist"; filename="words.txt"')
      expect(requestBody).toContain('api\nwww\n')
      saved = {...config, subdomains: ['api', 'www'], wordlist_filename: 'words.txt', wordlist_import: {skipped_invalid:1,skipped_comments:1,duplicates:0,examples:["Line 4: 'bad/entry' — Invalid DNS name"]}}
      json = {id: 'dns-scan', ...saved}
    } else if(path.endsWith('/scans/dns-scan')) {
      if(route.request().method()==='PATCH'){
        const changes=route.request().postDataJSON()
        expect(changes).not.toHaveProperty('subdomains')
        expect(changes).not.toHaveProperty('wordlist_filename')
        expect(changes).not.toHaveProperty('wordlist_import')
        saved={...saved,...changes}
      }
      json = {id: 'dns-scan', name: saved?.name, config: saved, target_summary: 'example.test (2 DNS candidates)'}
    } else if(path.endsWith('/runs/dns-run')) {
      json = {id: 'dns-run', config_snapshot: saved, status: 'completed', current_stage: 'consolidation', processed: 1, total: 1, counts: {subdomains: 1}}
    } else if(path.endsWith('/runs/dns-run/subdomains')) {
      json = {items: [{id: 'dns-result', identity: 'api.example.test', evidence: {hostname: 'api.example.test', addresses: ['192.0.2.5']}}], total: 1, total_pages: 1}
    }
    await route.fulfill({json})
  })
  await page.goto('/scans/new')
  await expect(page.getByLabel('Scan mode')).toHaveValue('network')
  await page.getByLabel('Scan mode').selectOption('subdomain')
  await expect(page.getByLabel('Authorized IP addresses / CIDRs')).toHaveCount(0)
  await expect(page.getByLabel('Scanner timeout (seconds)')).toHaveCount(0)
  await expect(page.getByLabel('Network timing')).toHaveCount(0)
  await page.getByLabel('Request timeout (seconds)').fill('0.75')
  await page.getByLabel('Maximum threads').fill('37')
  await page.getByLabel('Scan name').fill('DNS browser test')
  await page.getByLabel('Base domain').fill('example.test')
  await page.getByLabel('Subdomain wordlist').selectOption('file')
  await page.getByLabel('Import wordlist (.txt)').setInputFiles({name: 'words.txt', mimeType: 'text/plain', buffer: Buffer.from('api\nwww\n# comment\nbad/entry\n')})
  await expect(page.getByLabel('Subdomains to test')).toHaveCount(0)
  await expect(page.getByRole('status')).toContainText('words.txt')
  await expect(page.getByLabel('Subdomain wordlist')).toHaveValue('file')
  await page.getByRole('button', {name: 'Save scan', exact: true}).click()
  await expect(page.getByRole('heading', {name: 'DNS browser test', exact: true})).toBeVisible()
  await expect(page.getByRole('region',{name:'Wordlist import summary'})).toContainText('1 invalid lines skipped')
  await expect(page.getByRole('region',{name:'Wordlist import summary'})).toContainText("Line 4: 'bad/entry'")
  expect(saved).toMatchObject({mode: 'subdomain', domain: 'example.test', subdomains: ['api', 'www'], targets: [], urls: [], password_spray: false, request_timeout: 0.75, max_threads: 37})
  await page.getByRole('link', {name: 'Edit configuration'}).click()
  await expect(page.getByLabel('Scan mode')).toHaveValue('subdomain')
  await expect(page.getByLabel('Request timeout (seconds)')).toHaveValue('0.75')
  await expect(page.getByLabel('Maximum threads')).toHaveValue('37')
  await expect(page.getByLabel('Subdomains to test')).toHaveCount(0)
  await expect(page.getByRole('status')).toContainText('Saved wordlist: words.txt')
  await page.getByRole('button', {name: 'Save scan', exact: true}).click()
  await expect(page.getByRole('heading', {name: 'DNS browser test', exact: true})).toBeVisible()
  await page.goto('/scans/dns-scan/runs/dns-run')
  await expect(page.getByRole('columnheader', {name: 'Subdomain', exact: true})).toBeVisible()
  await expect(page.getByRole('cell', {name: 'api.example.test', exact: true})).toBeVisible()
  await expect(page.getByRole('cell', {name: '192.0.2.5', exact: true})).toBeVisible()
  await expect(page.getByRole('button', {name: 'Ports', exact: true})).toHaveCount(0)
})

test('Network and Subdomain results have separate views and filters', async ({page}) => {
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    let json: unknown = {items: [], total: 0, total_pages: 0}
    if(path.endsWith('/auth/me')) json = {username: 'operator'}
    else if(path.endsWith('/runs/network-run')) {
      // Historic configurations without a mode must still use Network results.
      json = {id: 'network-run', config_snapshot: {targets: ['192.0.2.1']}, status: 'completed', counts: {hosts: 1}, processed: 1, total: 1}
    } else if(path.endsWith('/runs/domain-run')) {
      json = {id: 'domain-run', config_snapshot: {mode: 'subdomain', domain: 'example.test', subdomains: ['api', 'www']}, status: 'completed', counts: {subdomains: 1}, processed: 1, total: 1}
    }
    await route.fulfill({json})
  })
  await page.goto('/scans/network-scan/runs/network-run')
  await expect(page.getByRole('heading', {name: 'Network scan results.'})).toBeVisible()
  await expect(page.getByRole('navigation', {name: 'Network result sections'})).toBeVisible()
  await expect(page.getByRole('button', {name: 'Services', exact: true})).toBeVisible()
  await expect(page.getByRole('button', {name: 'Subdomains', exact: true})).toHaveCount(0)
  await page.getByRole('button', {name: 'Findings', exact: true}).click()
  await expect(page.getByLabel('Status').getByRole('option', {name: 'new_host', exact: true})).toHaveCount(1)
  await expect(page.getByLabel('Status').getByRole('option', {name: 'subdomain', exact: true})).toHaveCount(0)

  await page.goto('/scans/domain-scan/runs/domain-run?tab=services')
  await expect(page.getByRole('heading', {name: 'Subdomain scan results.'})).toBeVisible()
  await expect(page.getByRole('navigation', {name: 'Subdomain result sections'})).toBeVisible()
  await expect(page.getByRole('region', {name: 'DNS scan scope'})).toContainText('example.test')
  await expect(page.getByRole('columnheader', {name: 'Subdomain', exact: true})).toBeVisible()
  await expect(page.getByLabel('Status')).toHaveCount(0)
  await expect(page.getByRole('progressbar')).toHaveAccessibleName('DNS wordlist progress')
  await expect(page.getByRole('button', {name: 'Services', exact: true})).toHaveCount(0)
  await expect(page.getByText('Wordlist entries', {exact: true})).toBeVisible()
  await page.getByRole('button', {name: 'Findings', exact: true}).click()
  await expect(page.getByLabel('Status').getByRole('option', {name: 'subdomain', exact: true})).toHaveCount(1)
  await expect(page.getByLabel('Status').getByRole('option', {name: 'new_host', exact: true})).toHaveCount(0)
})


test('Network timing and concurrency are saved and restored', async ({page}) => {
  let config: Record<string, any> | undefined
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    let json: unknown = {items: [], total: 0, total_pages: 0}
    if(path.endsWith('/auth/me')) json = {username: 'operator'}
    else if(path.endsWith('/scans') && route.request().method()==='POST') {
      config=route.request().postDataJSON()
      json={id:'timing-scan'}
    } else if(path.endsWith('/scans/timing-scan')) {
      json={id:'timing-scan',name:config?.name,config,target_summary:'192.0.2.1'}
    }
    await route.fulfill({json})
  })
  await page.goto('/scans/new')
  await page.getByLabel('Scan name').fill('Network timing test')
  await page.getByLabel('Authorized IP addresses / CIDRs').fill('192.0.2.1')
  await page.getByLabel('Request timeout (seconds)').fill('1.25')
  await page.getByLabel('Maximum threads').fill('48')
  await page.getByLabel('Network timing').selectOption('4')
  await page.getByRole('button',{name:'Save scan',exact:true}).click()
  await expect(page.getByRole('heading',{name:'Network timing test',exact:true})).toBeVisible()
  expect(config).toMatchObject({mode:'network',request_timeout:1.25,max_threads:48,network_timing:4})
  expect(config).not.toHaveProperty('timeout')
  await page.getByRole('link',{name:'Edit configuration'}).click()
  await expect(page.getByLabel('Request timeout (seconds)')).toHaveValue('1.25')
  await expect(page.getByLabel('Maximum threads')).toHaveValue('48')
  await expect(page.getByLabel('Network timing')).toHaveValue('4')
})


test('DNS progress and positive results update while running and remain after stop', async ({page}) => {
  let processed=0,status='running'
  let rows: Record<string, unknown>[]=[]
  const words=Array.from({length:5000},(_,index)=>`name${index}`)
  await page.route('**/api/v1/**',async route=>{
    const path=new URL(route.request().url()).pathname
    let json:unknown={items:[],total:0,total_pages:0}
    if(path.endsWith('/auth/me'))json={username:'operator'}
    else if(path.endsWith('/runs/live-dns'))json={id:'live-dns',status,processed,total:5000,current_stage:'dns',counts:{subdomains:rows.length},config_snapshot:{mode:'subdomain',domain:'example.test',subdomains:words}}
    else if(path.endsWith('/runs/live-dns/subdomains'))json={items:rows,total:rows.length,total_pages:rows.length?1:0}
    await route.fulfill({json})
  })
  await page.goto('/scans/dns/runs/live-dns')
  const progress=page.getByRole('progressbar',{name:'DNS wordlist progress'})
  await expect(progress).toHaveAttribute('max','5000')
  await expect(page.getByText('No results found.')).toBeVisible()
  processed=15
  rows=[{id:'live-result-1',identity:'api.example.test',evidence:{addresses:['192.0.2.1']}}]
  await expect(progress).toHaveAttribute('value','15')
  await expect(page.getByText(/15 \/ 5000 names tested/)).toBeVisible()
  await expect(page.getByRole('cell',{name:'api.example.test',exact:true})).toBeVisible()
  await expect(page.getByRole('button',{name:'Stop',exact:true})).toBeVisible()
  status='stopped';processed=16
  rows=[...rows,{id:'live-result-2',identity:'www.example.test',evidence:{addresses:['192.0.2.2']}}]
  await expect(page.getByRole('button',{name:'Stop',exact:true})).toHaveCount(0)
  await expect(progress).toHaveAttribute('value','16')
  await expect(page.getByRole('cell',{name:'www.example.test',exact:true})).toBeVisible()
  await expect(page.getByRole('cell',{name:'api.example.test',exact:true})).toBeVisible()
})
