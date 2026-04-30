CREATE TABLE IF NOT EXISTS public.sboms (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    document JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_public_sboms_org ON public.sboms(org_id);
