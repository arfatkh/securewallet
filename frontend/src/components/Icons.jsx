// Hand-drawn 24px stroke icons, one visual weight across the app.
const I = ({ size = 20, children, ...p }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
       strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...p}>{children}</svg>
)

export const Home = p => <I {...p}><path d="M4 10.5 12 4l8 6.5V19a1 1 0 0 1-1 1h-4.5v-5.5h-5V20H5a1 1 0 0 1-1-1z" /></I>
export const Send = p => <I {...p}><path d="M4.5 12h13M13 6.5 18.5 12 13 17.5" /></I>
export const Activity = p => <I {...p}><path d="M5 7h14M5 12h14M5 17h9" /></I>
export const Shield = p => <I {...p}><path d="M12 3.5 5 6.2v5.3c0 4.3 2.9 7.5 7 9 4.1-1.5 7-4.7 7-9V6.2z" /><path d="m9.3 12.2 1.9 1.9 3.6-3.8" /></I>
export const Ledger = p => <I {...p}><rect x="5" y="3.5" width="14" height="17" rx="2" /><path d="M8.5 8h7M8.5 12h7M8.5 16h4" /></I>
export const Flask = p => <I {...p}><path d="M9.5 3.5h5M10.5 3.5v5.2L5.4 17.6A2 2 0 0 0 7.1 20.5h9.8a2 2 0 0 0 1.7-2.9l-5.1-8.9V3.5" /><path d="M7.6 14.5h8.8" /></I>
export const Eye = p => <I {...p}><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" /><circle cx="12" cy="12" r="2.8" /></I>
export const EyeOff = p => <I {...p}><path d="M3.5 3.5l17 17M10 5.8a9 9 0 0 1 2-.3c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.9 3.6M6.4 7.4C3.9 9.1 2.5 12 2.5 12s3.5 6.5 9.5 6.5a8.6 8.6 0 0 0 4.3-1.1" /><path d="M9.9 10a2.8 2.8 0 0 0 4 4" /></I>
export const Key = p => <I {...p}><circle cx="8" cy="15" r="3.8" /><path d="m10.8 12.3 8.7-8.7M16.5 6.5l2.4 2.4M14 9l2 2" /></I>
export const Fingerprint = p => <I {...p}><path d="M12 11v3.5c0 2-.6 3.9-1.6 5.5M8.1 20c.9-1.6 1.4-3.5 1.4-5.5V11a2.5 2.5 0 0 1 5 0v1M17 13.5c0 2.1-.4 4.1-1.1 5.9M5.5 17.5c.4-1 .5-2 .5-3V11a6 6 0 0 1 10.3-4.2M18.8 9.5c.1.5.2 1 .2 1.5" /></I>
export const Out = p => <I {...p}><path d="M14.5 4.5H18a1.5 1.5 0 0 1 1.5 1.5v12a1.5 1.5 0 0 1-1.5 1.5h-3.5M10 16.5 5.5 12 10 7.5M5.5 12h10" /></I>
export const Check = p => <I {...p}><path d="m5 12.5 4.5 4.5L19 7.5" /></I>
export const X = p => <I {...p}><path d="M6 6l12 12M18 6 6 18" /></I>
export const Alert = p => <I {...p}><path d="M12 4 2.8 19.5h18.4z" /><path d="M12 10v4M12 17h.01" /></I>
export const Info = p => <I {...p}><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5M12 8h.01" /></I>
export const Plus = p => <I {...p}><path d="M12 5v14M5 12h14" /></I>
export const Back = p => <I {...p}><path d="M19 12H5M11 6l-6 6 6 6" /></I>
export const Arrow = p => <I {...p}><path d="M7 17 17 7M9 7h8v8" /></I>
export const ArrowIn = p => <I {...p}><path d="M17 7 7 17M15 17H7V9" /></I>
export const Trace = p => <I {...p}><path d="M4 6h4M4 12h7M4 18h4" /><circle cx="15" cy="6" r="2" /><circle cx="18" cy="12" r="2" /><circle cx="15" cy="18" r="2" /><path d="M13 6H8M16 12h-5M13 18H8" /></I>
export const Play = p => <I {...p}><path d="M8 5.5v13l10-6.5z" /></I>
export const Refresh = p => <I {...p}><path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4" /></I>
export const Copy = p => <I {...p}><rect x="8.5" y="8.5" width="11" height="11" rx="2" /><path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5" /></I>
export const Search = p => <I {...p}><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.4-4.4" /></I>
export const Clock = p => <I {...p}><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></I>
export const Lock = p => <I {...p}><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7" /></I>

// Brand seal: a cobalt disc with a fine inner ring (like an embossed bank seal) and an "S" monogram.
export function Logo({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="logo">
      <circle cx="16" cy="16" r="16" fill="#2747D6" />
      <circle cx="16" cy="16" r="12.6" fill="none" stroke="#F6F2EA" strokeOpacity=".55" strokeWidth=".8" strokeDasharray="1.2 1.1" />
      <path d="M20.2 11.6c-.8-1.3-2.3-2.1-4.2-2.1-2.4 0-4 1.3-4 3.1 0 4.1 8.4 2.4 8.4 6.6 0 1.9-1.8 3.3-4.4 3.3-2 0-3.6-.9-4.4-2.3"
            fill="none" stroke="#FFFDF8" strokeWidth="2.1" strokeLinecap="round" />
    </svg>
  )
}
