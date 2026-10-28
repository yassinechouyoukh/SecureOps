import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
type Point={time:string,events:number}
export default function EventVolumeChart({data}:{data:Point[]}) {
  return <ResponsiveContainer width="100%" height="100%"><AreaChart data={data} margin={{top:10,right:8,left:-20,bottom:0}}><defs><linearGradient id="blueFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#5e9bff" stopOpacity={.28}/><stop offset="100%" stopColor="#5e9bff" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#202a3a" vertical={false}/><XAxis dataKey="time" tick={{fill:'#758198',fontSize:11}} axisLine={false} tickLine={false}/><YAxis tick={{fill:'#758198',fontSize:11}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:'#121b29',border:'1px solid #2a3649',borderRadius:9,color:'#edf2fa'}}/><Area type="monotone" dataKey="events" stroke="#70a8ff" strokeWidth={2} fill="url(#blueFill)"/></AreaChart></ResponsiveContainer>
}
