<script setup lang="ts">
import { computed, ref, watch, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from './api'
const props=withDefaults(defineProps<{endpoint:string,columns:{key:string,label:string,sortable?:boolean}[],refresh?:number,filterStatus?:boolean,statusOptions?:string[],queryKey?:string}>(),{refresh:0,queryKey:'table'})
const route=useRoute(),router=useRouter()
const items=ref<Record<string,any>[]>([]),total=ref(0),pages=ref(0),loading=ref(true),error=ref('')
const key=(x:string)=>`${props.queryKey}_${x}`
const search=ref(String(route.query[key('search')]||'')),page=ref(Number(route.query[key('page')])||1)
const size=ref(Number(route.query[key('size')])||25),status=ref(String(route.query[key('status')]||''))
const order=ref(String(route.query[key('order')]||'desc')),sort=ref(String(route.query[key('sort')]||'created_at'))
const sortable=computed(()=>[...new Set(['created_at',...props.columns.filter(c=>c.sortable!==false&&c.key!=='selected').map(c=>c.key)])])
const csvUrl=computed(()=>props.endpoint+'/export.csv?'+new URLSearchParams({search:search.value,status:status.value,sort_by:sort.value,sort_order:order.value}))
function sortColumn(field:string){order.value=sort.value===field&&order.value==='asc'?'desc':'asc';sort.value=field;searchChanged()}
let version=0, timer:ReturnType<typeof setInterval>|undefined
async function load(quiet=false){const current=++version;if(!quiet)loading.value=true;error.value='';try{
  const query=new URLSearchParams({page:String(page.value),page_size:String(size.value),search:search.value,sort_by:sort.value,sort_order:order.value})
  if(status.value)query.set('status',status.value)
  const data=await api(props.endpoint+'?'+query)
  if(current!==version)return
  items.value=data.items;total.value=data.total;pages.value=data.total_pages
}catch(e){if(current===version)error.value=(e as Error).message}finally{if(current===version)loading.value=false}}
function remember(){void router.replace({query:{...route.query,[key('page')]:String(page.value),[key('size')]:String(size.value),[key('search')]:search.value,[key('status')]:status.value,[key('sort')]:sort.value,[key('order')]:order.value}})}
function searchChanged(){page.value=1;remember();void load()}
watch(()=>props.endpoint,()=>{page.value=1;void load()},{immediate:true})
watch(()=>props.refresh,(refresh,previous)=>{if(timer)clearInterval(timer);if(refresh)timer=setInterval(()=>void load(true),refresh);else if(previous)void load(true)},{immediate:true})
onUnmounted(()=>{version++;if(timer)clearInterval(timer)})
defineExpose({load})
function display(value:unknown):string{if(value===null||value===undefined||value==='')return '—';if(Array.isArray(value))return value.map(display).join('\n');if(typeof value==='object')return Object.entries(value).map(([k,v])=>`${k}: ${display(v)}`).join('\n');return String(value)}
function details(value:any):string {if(value?.response_headers)return value.response_headers.map(([k,v]:[string,string])=>`${k}: ${v}`).join('\n');return display(value)}
</script>
<template><section class="panel table-panel"><div class="table-toolbar"><label class="search">Search<input v-model="search" placeholder="Search results…" type="search" @keydown.enter.prevent="searchChanged"></label><button type="button" class="subtle" @click="searchChanged">Search</button><label v-if="filterStatus">Status<select v-model="status" @change="searchChanged"><option value="">All statuses</option><option v-for="s in statusOptions || ['never','queued','running','pausing','paused','stopping','stopped','completed','failed']" :key="s">{{s}}</option></select></label><label>Sort by<select v-model="sort" @change="searchChanged"><option v-for="field in sortable" :key="field" :value="field">{{field.replaceAll('_',' ')}}</option></select></label><label>Order<select v-model="order" @change="searchChanged"><option value="desc">Descending</option><option value="asc">Ascending</option></select></label><label>Per page<select v-model="size" @change="searchChanged"><option :value="10">10</option><option :value="25">25</option><option :value="100">100</option></select></label><button type="button" class="subtle" @click="load()">Refresh</button><a v-if="endpoint.startsWith('/runs/')" class="button subtle" :href="csvUrl" download>Export CSV</a></div>
<p v-if="error" class="error" role="alert">{{error}}</p><p v-if="loading" role="status" class="empty">Loading…</p>
<div v-else class="table-wrap"><table><thead><tr><th v-for="c in columns" :key="c.key" scope="col" :aria-sort="sort===c.key?(order==='asc'?'ascending':'descending'):'none'"><button v-if="c.sortable!==false&&c.key!=='selected'" type="button" class="text-button" @click="sortColumn(c.key)">{{c.label}} <span aria-hidden="true">{{sort===c.key?(order==='asc'?'↑':'↓'):'↕'}}</span></button><span v-else>{{c.label}}</span></th><th v-if="$slots.actions" scope="col">Actions</th></tr></thead><tbody><tr v-for="row in items" :key="row.id"><td v-for="c in columns" :key="c.key"><slot :name="c.key" :row="row" :value="row[c.key]"><span v-if="['status','last_status','change'].includes(c.key)" class="badge" :data-status="row[c.key]">{{display(row[c.key])}}</span><pre v-else-if="c.key==='details'" class="response-headers">{{details(row[c.key])}}</pre><span v-else class="cell-lines">{{display(row[c.key])}}</span></slot></td><td v-if="$slots.actions"><div class="actions"><slot name="actions" :row="row"/></div></td></tr></tbody></table><p v-if="!items.length" class="empty">No results found.</p></div>
<div class="pagination"><span>{{total}} items · Page {{page}} of {{Math.max(1,pages)}}</span><div class="actions"><button type="button" class="subtle" :disabled="page<=1" @click="page--;remember();load()">Previous</button><button type="button" class="subtle" :disabled="page>=pages" @click="page++;remember();load()">Next</button></div></div></section></template>
