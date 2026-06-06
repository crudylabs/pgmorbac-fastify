export const orgResponse = {
    type: 'object',
    properties: {
        id:        { type: 'string', format: 'uuid' },
        name:      { type: 'string' },
        parent_id: { type: 'string', format: 'uuid', nullable: true },
        metadata:  { type: 'object' },
    },
};

export const roleResponse = {
    type: 'object',
    properties: {
        id:          { type: 'string', format: 'uuid' },
        org_id:      { type: 'string', format: 'uuid' },
        org_name:    { type: 'string' },
        name:        { type: 'string' },
        description: { type: 'string', nullable: true },
    },
};

export const ruleResponse = {
    type: 'object',
    properties: {
        id:        { type: 'string', format: 'uuid' },
        role_id:   { type: 'string', format: 'uuid' },
        org_id:    { type: 'string', format: 'uuid' },
        org_name:  { type: 'string' },
        role_name: { type: 'string' },
        activity:  { type: 'string' },
        view:      { type: 'string' },
        modality:  { type: 'string', enum: ['permission', 'prohibition'] },
        priority:  { type: 'integer', nullable: true },
        scope:     { type: 'string' },
    },
};

export const userResponse = {
    type: 'object',
    properties: {
        id:           { type: 'string', format: 'uuid' },
        email:        { type: 'string', format: 'email' },
        name:         { type: 'string' },
        account_type:    { type: 'string', enum: ['user', 'system', 'service'] },
        is_active:       { type: 'boolean' },
        needs_placement: { type: 'boolean' },
        created_at:      { type: 'string', format: 'date-time' },
        roles: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    role_id:   { type: 'string', format: 'uuid' },
                    role_name: { type: 'string' },
                    org_id:    { type: 'string', format: 'uuid' },
                    org_name:  { type: 'string' },
                },
            },
        },
    },
};

export const crossOrgRuleResponse = {
    type: 'object',
    properties: {
        id:               { type: 'string', format: 'uuid' },
        source_org_id:    { type: 'string', format: 'uuid' },
        source_role_id:   { type: 'string', format: 'uuid' },
        target_org_id:    { type: 'string', format: 'uuid' },
        source_org_name:  { type: 'string' },
        source_role_name: { type: 'string' },
        target_org_name:  { type: 'string' },
        activity:         { type: 'string' },
        view:             { type: 'string' },
        modality:         { type: 'string', enum: ['permission', 'prohibition'] },
        priority:         { type: 'integer', nullable: true },
    },
};

export const userRuleResponse = {
    type: 'object',
    properties: {
        id:         { type: 'string', format: 'uuid' },
        user_id:    { type: 'string', format: 'uuid' },
        org_id:     { type: 'string', format: 'uuid' },
        user_name:  { type: 'string' },
        user_email: { type: 'string', nullable: true },
        org_name:   { type: 'string' },
        activity:   { type: 'string' },
        view:       { type: 'string' },
        modality:   { type: 'string', enum: ['permission', 'prohibition'] },
        priority:   { type: 'integer', nullable: true },
    },
};

export const globalRuleResponse = {
    type: 'object',
    properties: {
        id:                  { type: 'string', format: 'uuid' },
        user_id:             { type: 'string', format: 'uuid', nullable: true },
        user_name:           { type: 'string', nullable: true },
        user_email:          { type: 'string', nullable: true },
        activity:            { type: 'string', nullable: true },
        view:                { type: 'string', nullable: true },
        modality:            { type: 'string', enum: ['permission', 'prohibition'] },
        priority:            { type: 'integer', nullable: true },
        is_system_principal: { type: 'boolean' },
    },
};

export const delegationResponse = {
    type: 'object',
    properties: {
        id:              { type: 'string', format: 'uuid' },
        delegator_id:    { type: 'string', format: 'uuid' },
        delegatee_id:    { type: 'string', format: 'uuid' },
        delegator_name:  { type: 'string', nullable: true },
        delegator_email: { type: 'string', nullable: true },
        delegatee_name:  { type: 'string', nullable: true },
        delegatee_email: { type: 'string', nullable: true },
        role_id:         { type: 'string', format: 'uuid' },
        role_name:       { type: 'string' },
        org_id:          { type: 'string', format: 'uuid' },
        org_name:        { type: 'string' },
        valid_from:      { type: 'string', format: 'date-time' },
        valid_until:     { type: 'string', format: 'date-time' },
        revoked:         { type: 'boolean' },
        created_at:      { type: 'string', format: 'date-time' },
    },
};

export const notFound     = { description: 'Resource not found.' };
export const forbidden    = { description: 'Insufficient permissions.' };
export const unauthorized = { description: 'Missing or invalid token.' };
export const badRequest   = { description: 'X-Org-Id header is required.' };
