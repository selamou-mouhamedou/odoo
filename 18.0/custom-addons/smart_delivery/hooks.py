# -*- coding: utf-8 -*-

from odoo import SUPERUSER_ID, api
import logging
import base64

_logger = logging.getLogger(__name__)

# Placeholder image (1x1 transparent PNG) for existing livreurs without documents
PLACEHOLDER_IMAGE = base64.b64encode(
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01'
    b'\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
).decode('utf-8')


def pre_init_hook(env):
    """Set default values for existing livreurs before adding required fields"""
    cr = env.cr
    
    # Check if the delivery_livreur table exists
    cr.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'delivery_livreur'
        );
    """)
    table_exists = cr.fetchone()[0]
    
    if not table_exists:
        _logger.info("Table delivery_livreur does not exist yet, skipping pre_init_hook")
        return
    
    # Check if the new columns already exist
    cr.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'delivery_livreur' AND column_name = 'nni';
    """)
    nni_exists = cr.fetchone()
    
    if nni_exists:
        _logger.info("Column 'nni' already exists, skipping migration")
        return
    
    _logger.info("Adding default values for new required livreur fields...")
    
    # Add the new columns with default values for existing records
    # NNI column with generated default values
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS nni VARCHAR;
    """)
    
    # Generate unique NNI for existing livreurs (format: LEGACY-{id})
    cr.execute("""
        UPDATE delivery_livreur 
        SET nni = 'LEGACY-' || id::text 
        WHERE nni IS NULL;
    """)
    
    # Add photo columns with placeholder images
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS nni_photo BYTEA;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS livreur_photo BYTEA;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS carte_grise_photo BYTEA;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS assurance_photo BYTEA;
    """)
    
    # Add filename columns
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS nni_photo_filename VARCHAR;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS livreur_photo_filename VARCHAR;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS carte_grise_photo_filename VARCHAR;
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS assurance_photo_filename VARCHAR;
    """)
    
    # Add registration_status column
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS registration_status VARCHAR DEFAULT 'approved';
    """)
    cr.execute("""
        ALTER TABLE delivery_livreur 
        ADD COLUMN IF NOT EXISTS rejection_reason TEXT;
    """)
    
    # Set placeholder image for existing records
    cr.execute("""
        UPDATE delivery_livreur 
        SET nni_photo = decode(%s, 'base64'),
            nni_photo_filename = 'placeholder.png',
            livreur_photo = decode(%s, 'base64'),
            livreur_photo_filename = 'placeholder.png',
            carte_grise_photo = decode(%s, 'base64'),
            carte_grise_photo_filename = 'placeholder.png',
            assurance_photo = decode(%s, 'base64'),
            assurance_photo_filename = 'placeholder.png',
            registration_status = 'approved'
        WHERE nni_photo IS NULL OR livreur_photo IS NULL 
              OR carte_grise_photo IS NULL OR assurance_photo IS NULL;
    """, (PLACEHOLDER_IMAGE, PLACEHOLDER_IMAGE, PLACEHOLDER_IMAGE, PLACEHOLDER_IMAGE))
    
    _logger.info("Successfully added default values for existing livreurs")


def post_init_hook(env):
    """Initialise les règles de secteur par défaut après l'installation du module"""
    _create_default_sector_rules(env)
    _migrate_existing_enterprise_users(env)
    _migrate_livreur_legacy_documents(env)


def post_load():
    """Hook appelé après le chargement du module - utile pour les mises à jour"""
    pass


def uninstall_hook(env):
    """Nettoie les données lors de la désinstallation"""
    pass


def _create_default_sector_rules(env):
    """Crée ou met à jour les règles de secteur par défaut"""
    SectorRule = env['sector.rule']
    
    # Définition des règles par défaut
    default_rules = [
        {
            'sector_type': 'standard',
            'otp_required': False,
            'signature_required': False,
            'photo_required': False,
            'biometric_required': False,
            'description': 'Livraison standard sans exigences particulières. Dépôt simple au destinataire.',
        },
        {
            'sector_type': 'premium',
            'otp_required': True,
            'signature_required': True,
            'photo_required': False,
            'biometric_required': False,
            'description': 'Livraison premium nécessitant une vérification OTP et une signature du destinataire.',
        },
        {
            'sector_type': 'express',
            'otp_required': True,
            'signature_required': False,
            'photo_required': True,
            'biometric_required': False,
            'description': 'Livraison express avec vérification OTP et photo de preuve de livraison.',
        },
        {
            'sector_type': 'fragile',
            'otp_required': True,
            'signature_required': True,
            'photo_required': True,
            'biometric_required': False,
            'description': 'Livraison de colis fragiles avec OTP, signature et photo obligatoires pour prouver l\'état du colis.',
        },
        {
            'sector_type': 'medical',
            'otp_required': True,
            'signature_required': True,
            'photo_required': True,
            'biometric_required': True,
            'description': 'Livraison médicale avec protocole complet: OTP, signature, photo et vérification biométrique du destinataire.',
        },
    ]
    
    for rule_vals in default_rules:
        # Chercher si la règle existe déjà
        existing_rule = SectorRule.search([
            ('sector_type', '=', rule_vals['sector_type'])
        ], limit=1)
        
        if existing_rule:
            # Mettre à jour la règle existante
            existing_rule.write(rule_vals)
        else:
            # Créer la nouvelle règle
            SectorRule.create(rule_vals)


def _migrate_existing_enterprise_users(env):
    """Create delivery.enterprise records for existing enterprise users without one"""
    _logger.info("Migrating existing enterprise users to delivery.enterprise model...")
    
    # Get the enterprise group
    enterprise_group = env.ref('smart_delivery.group_enterprise', raise_if_not_found=False)
    if not enterprise_group:
        _logger.warning("Enterprise group not found, skipping migration")
        return
    
    # Get the admin group to exclude admins (they have enterprise group implied)
    admin_group = env.ref('smart_delivery.group_admin', raise_if_not_found=False)
    
    # Find all users with enterprise group
    enterprise_users = env['res.users'].sudo().search([
        ('groups_id', 'in', [enterprise_group.id]),
        ('active', 'in', [True, False]),  # Include inactive users too
    ])
    
    # Exclude admin users (they have enterprise group implied but are not enterprises)
    if admin_group:
        enterprise_users = enterprise_users.filtered(lambda u: admin_group not in u.groups_id)
    
    Enterprise = env['delivery.enterprise'].sudo()
    migrated_count = 0
    
    for user in enterprise_users:
        # Check if this user already has an enterprise record
        existing_enterprise = Enterprise.search([('user_id', '=', user.id)], limit=1)
        if existing_enterprise:
            continue
        
        # Check if there's an enterprise with the same email
        existing_by_email = Enterprise.search([('email', '=', user.email or user.login)], limit=1)
        if existing_by_email:
            # Link the user to existing enterprise
            existing_by_email.write({'user_id': user.id})
            _logger.info(f"Linked user {user.login} to existing enterprise {existing_by_email.name}")
            continue
        
        # Create a new enterprise record for this user
        partner = user.partner_id
        enterprise_vals = {
            'name': partner.name if partner else user.name,
            'email': user.email or user.login,
            'phone': partner.phone or user.phone or 'N/A',
            'user_id': user.id,
            'partner_id': partner.id if partner else False,
            'logo': partner.image_1920 if partner else False,
            'address': partner.street if partner else False,
            'city': partner.city if partner else False,
            'website': partner.website if partner else False,
            'description': partner.comment if partner else False,
            'registration_status': 'approved',  # Existing users are considered approved
        }
        
        try:
            # Use SQL to avoid triggering create logic that would create duplicate user/partner
            env.cr.execute("""
                INSERT INTO delivery_enterprise 
                (name, email, phone, user_id, partner_id, logo, address, city, website, description, 
                 registration_status, create_uid, create_date, write_uid, write_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, NOW())
                ON CONFLICT (email) DO NOTHING
                RETURNING id
            """, (
                enterprise_vals['name'],
                enterprise_vals['email'],
                enterprise_vals['phone'],
                enterprise_vals['user_id'],
                enterprise_vals['partner_id'],
                enterprise_vals['logo'],
                enterprise_vals['address'],
                enterprise_vals['city'],
                enterprise_vals['website'],
                enterprise_vals['description'],
                enterprise_vals['registration_status'],
                env.uid,
                env.uid,
            ))
            result = env.cr.fetchone()
            if result:
                migrated_count += 1
                _logger.info(f"Created enterprise record for user: {user.login}")
        except Exception as e:
            _logger.warning(f"Could not migrate user {user.login}: {e}")
            continue
    
    _logger.info(f"Migration complete: {migrated_count} enterprise records created")


def _migrate_livreur_legacy_documents(env):
    """
    Migrate legacy document fields (nni_photo, livreur_photo, carte_grise_photo, assurance_photo)
    to the new dynamic livreur.document model.
    
    This allows existing livreurs to keep their documents while new livreurs 
    can upload any document type they want.
    """
    _logger.info("Migrating legacy livreur documents to dynamic document model...")
    
    Livreur = env['delivery.livreur'].sudo()
    LivreurDocument = env['livreur.document'].sudo()
    
    # Find all livreurs that have legacy photo fields but might not have documents
    livreurs = Livreur.search([])
    migrated_count = 0
    
    # Legacy field mappings: (field_name, filename_field, document_name)
    legacy_fields = [
        ('nni_photo', 'nni_photo_filename', 'Photo NNI'),
        ('livreur_photo', 'livreur_photo_filename', 'Photo du Livreur'),
        ('carte_grise_photo', 'carte_grise_photo_filename', 'Carte Grise'),
        ('assurance_photo', 'assurance_photo_filename', 'Assurance'),
    ]
    
    for livreur in livreurs:
        documents_to_create = []
        
        for photo_field, filename_field, doc_name in legacy_fields:
            photo_data = getattr(livreur, photo_field, None)
            
            # Skip if no photo data or if it's the placeholder image
            if not photo_data:
                continue
            
            # Check if this document already exists for this livreur
            existing_doc = LivreurDocument.search([
                ('livreur_id', '=', livreur.id),
                ('name', '=', doc_name)
            ], limit=1)
            
            if existing_doc:
                continue  # Document already migrated
            
            filename = getattr(livreur, filename_field, None) or f'{doc_name}.jpg'
            
            # Skip placeholder images (they have placeholder.png filename)
            if filename == 'placeholder.png':
                continue
            
            documents_to_create.append({
                'livreur_id': livreur.id,
                'name': doc_name,
                'photo': photo_data,
                'photo_filename': filename,
                'is_verified': livreur.verified,
                'sequence': (len(documents_to_create) + 1) * 10,
            })
        
        if documents_to_create:
            try:
                LivreurDocument.create(documents_to_create)
                migrated_count += 1
                _logger.info(f"Migrated {len(documents_to_create)} documents for livreur: {livreur.name}")
            except Exception as e:
                _logger.warning(f"Could not migrate documents for livreur {livreur.name}: {e}")
                continue
    
    _logger.info(f"Document migration complete: {migrated_count} livreurs with migrated documents")
