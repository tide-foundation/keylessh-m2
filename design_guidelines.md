# KeyleSSH Frontend Design Guidelines

## Design Approach

**Selected Approach**: Design System + Developer Tool References  
**Justification**: This is a utility-focused productivity tool for DevOps/developers requiring efficiency, clarity, and stability. Drawing inspiration from Linear's precision, Vercel's developer-focused UI, and GitHub's information density.

**Core Principles**:
- Terminal-first: The SSH console is the hero feature
- Information clarity over decoration
- Instant feedback and system status visibility
- Professional developer aesthetic

## Typography System

**Font Stack**:
- Primary: Inter (via Google Fonts CDN) - UI text, labels, buttons
- Monospace: JetBrains Mono (via Google Fonts CDN) - terminal, code, server IDs

**Type Scale**:
- Hero/Page Titles: text-2xl font-semibold
- Section Headers: text-lg font-medium
- Body Text: text-sm font-normal
- Labels/Metadata: text-xs font-medium uppercase tracking-wide
- Terminal Text: text-sm (monospace)

## Layout System

**Spacing Primitives**: Use Tailwind units of 2, 4, 6, and 8 exclusively
- Component padding: p-4, p-6
- Section spacing: gap-4, gap-6, space-y-6
- Page margins: p-6, p-8
- Grid gaps: gap-4

**Application Structure**:
- Persistent left sidebar: w-64 fixed left-0 h-screen (navigation)
- Main content area: ml-64 min-h-screen (with top bar and content)
- Top bar height: h-16 (user info, breadcrumbs, actions)
- Terminal full-screen: absolute inset-0 minus top bar

## Component Library

### Navigation Sidebar
- Fixed width 256px (w-64)
- Logo/branding at top with p-6
- Navigation items: py-2 px-4 rounded-md
- Active state: distinct visual treatment
- Role indicator badge (Admin/User)
- Bottom section: user profile + logout

### Top Bar
- Full width with border-b
- Left: Breadcrumb navigation (text-sm)
- Right: User avatar + name + role badge + logout button
- Height: 64px (h-16)
- Items centered vertically

### Dashboard Cards
Server cards in grid layout:
- Grid: grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4
- Card structure: p-6 rounded-lg border
- Server name: text-base font-semibold
- Metadata row: flex items-center gap-4 text-xs (host, port, environment badge)
- SSH user selector: Dropdown or pill buttons
- Connect button: w-full mt-4

Recent/Active Sessions:
- List layout with dividers
- Each item: py-3 px-4
- Session info: server name + user + timestamp
- Status indicator dot + "Active" label

### Terminal Console Page
- Full viewport minus top bar
- Terminal occupies 100% of available space
- Connection status bar above terminal: h-10 px-4 (status indicator + text + reconnect button)
- Terminal container: flex-1 (fills remaining space)

### Admin Dashboard Tables
- Full-width responsive tables
- Header row: py-3 px-4 text-xs font-medium uppercase
- Data rows: py-4 px-4 text-sm border-t
- Action buttons: icon buttons or text links aligned right
- Filters/search: mb-6 flex gap-4 items-center

### Forms (Admin Create/Edit)
- Modal or slide-over panel approach
- Form fields: space-y-4
- Label: text-sm font-medium mb-1.5
- Input fields: w-full px-3 py-2 rounded-md border text-sm
- Toggle switches for enabled/disabled states
- Action buttons at bottom: flex gap-3 justify-end

### Status Indicators
- Connection states: inline-flex items-center gap-2
- Dot indicator: w-2 h-2 rounded-full
- Status text: text-xs font-medium
- Use in: sessions, server health, connection status

### Badges
- Role badges: px-2 py-0.5 rounded text-xs font-medium
- Environment badges (prod/staging/dev): px-2 py-1 rounded-full text-xs
- Count badges: Circular or pill shape

## Responsive Strategy

**Breakpoints**:
- Mobile (default): Stack everything, hide sidebar (hamburger menu)
- Tablet (md: 768px): Show sidebar, 2-column grids
- Desktop (lg: 1024px): Full layout, 3-column grids

**Mobile Adaptations**:
- Sidebar becomes overlay drawer
- Top bar: hamburger menu + title + user avatar only
- Server grid: Single column
- Terminal: Full screen with minimal chrome

## Terminal-Specific Design

**Terminal Container**:
- Render xterm.js with full container dimensions
- No padding inside terminal (terminal handles its own spacing)
- Terminal wrapper: overflow-hidden rounded-lg

**Terminal Controls**:
- Minimal UI overlay
- Connection status: Sticky top bar inside terminal viewport
- Copy/paste: Browser default or subtle floating toolbar
- Font size controls: Optional gear icon in top-right

## State Design Patterns

**Loading States**:
- Skeleton screens for dashboard cards: animate-pulse
- Spinner for quick actions: Small inline spinner
- Terminal connecting: Pulsing connection status indicator

**Empty States**:
- Centered content: flex flex-col items-center justify-center
- Icon (from Heroicons): w-12 h-12 mb-4
- Message: text-base font-medium
- Subtext: text-sm text-muted mt-2
- CTA button: mt-6

**Error States**:
- Alert banners: p-4 rounded-md border-l-4
- Icon + message inline
- Retry button when applicable

## Icon System

**Icon Library**: Heroicons (Outline for UI, Solid for emphasis)
- Navigation icons: 20px (w-5 h-5)
- Action buttons: 16px (w-4 h-4)
- Status indicators: 12px (w-3 h-3)
- Empty state icons: 48px (w-12 h-12)

## Animations

Use sparingly:
- Sidebar toggle: transition-transform duration-200
- Modal/drawer entry: slide-in-right or fade-in
- Loading spinners: animate-spin
- Toast notifications: slide-in-top with auto-dismiss

Avoid: Hover animations on terminal, scroll effects, complex transitions

## Accessibility

- Focus visible states on all interactive elements: focus:ring-2 focus:ring-offset-2
- Skip to terminal link for keyboard users
- ARIA labels on icon-only buttons
- Proper heading hierarchy (h1 → h2 → h3)
- Sufficient contrast ratios for terminal text
- Keyboard shortcuts documentation for terminal

## Images

**No hero images required** - This is a utility application, not marketing
**Avatar images**: User profile pictures in top bar and user management
**Server/Environment icons**: Optional small icons for server types (AWS, Docker, etc.) - use icon fonts instead