<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from './api'
const username=ref(''),password=ref(''),error=ref(''),busy=ref(false),router=useRouter()
async function login(){busy.value=true;error.value='';try{await api('/auth/login','POST',{username:username.value,password:password.value});password.value='';await router.push('/scans')}catch(e){error.value=(e as Error).message}finally{busy.value=false}}
</script>
<template><section class="login panel"><p class="eyebrow">YOUR ASSESSMENT WORKSPACE</p><h1>Welcome back.</h1><p class="muted">Sign in to manage scans and explore your network.</p><form @submit.prevent="login"><label>Username<input v-model="username" autocomplete="username" required autofocus></label><label>Password<input v-model="password" type="password" autocomplete="current-password" required></label><p v-if="error" class="error" role="alert">{{error}}</p><button :disabled="busy">{{busy?'Signing in…':'Sign in'}}</button></form><p class="muted">First time here? Create your account with the administrator CLI.</p></section></template>
