import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CredentialsSchema, Severity, Status } from './App'

describe('security workflow badges', () => {
  it('labels critical severity clearly', () => {
    render(<Severity value="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeTruthy()
  })
  it('renders readable alert status', () => {
    render(<Status value="FALSE_POSITIVE" />)
    expect(screen.getByText('FALSE POSITIVE')).toBeTruthy()
  })
  it('rejects malformed login credentials', () => {
    expect(CredentialsSchema.safeParse({email:'invalid',password:'short'}).success).toBe(false)
  })
})
