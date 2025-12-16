# Guide de Facturation Smart Delivery
# دليل الفوترة Smart Delivery

---

# 🇫🇷 FRANÇAIS

---

## 1. Vue d'ensemble du Système

Le module Smart Delivery intègre un système de facturation simple et efficace :

- **Prix configurables** : Les tarifs sont définis dans les Règles de Secteur
- **Paiement à la livraison** : Le destinataire paie en espèces
- **Factures Odoo** : Utilisation du module Facturation standard d'Odoo
- **Facturation par l'entreprise** : Chaque facture est émise au nom de l'entreprise qui crée la commande

### Flux de travail principal

```
COMMANDE → LIVRAISON → FACTURATION AUTO → PAIEMENT ESPÈCES
```

> 💰 **Mode de paiement unique :** Espèces à la livraison (COD - Cash On Delivery)

---

## 2. Configuration des Tarifs

### Où configurer les prix ?

**Emplacement :** Smart Delivery → Configuration → Règles de Secteur

Pour chaque type de secteur, vous pouvez définir :

| Paramètre | Description |
|-----------|-------------|
| **Prix de Base** | Tarif fixe pour ce type de livraison |
| **Frais par km** | Coût par kilomètre au-delà de la distance gratuite |
| **Distance gratuite** | Kilomètres inclus dans le prix de base (par défaut: 5 km) |

### Tarifs par défaut

| Type de Secteur | Prix de Base | Frais/km | Km Gratuits |
|-----------------|--------------|----------|-------------|
| Standard | 50 MRU | 10 MRU | 5 km |
| Premium | 100 MRU | 10 MRU | 5 km |
| Express | 150 MRU | 15 MRU | 5 km |
| Fragile | 120 MRU | 12 MRU | 5 km |
| Médical | 200 MRU | 20 MRU | 5 km |

### Formule de calcul

```
Frais de Distance = max(0, distance - km_gratuits) × frais_par_km
Total = Prix de Base + Frais de Distance
```

**Exemple :** Livraison Express de 12 km
- Prix de Base = 150 MRU
- Frais de Distance = (12 - 5) × 15 = 105 MRU
- **Total = 255 MRU (payé en espèces à la livraison)**

---

## 3. Les Étapes du Processus

### Étape 1 : Création de la Commande

**Par :** L'entreprise (via l'interface ou l'API)

- L'entreprise créé une commande de livraison
- Le type de secteur détermine automatiquement les tarifs
- La distance est calculée automatiquement

### Étape 2 : Livraison

Le livreur effectue la livraison et valide les conditions requises :

| Type | OTP | Signature | Photo | Biométrie |
|------|-----|-----------|-------|-----------|
| Standard | ❌ | ❌ | ❌ | ❌ |
| Premium | ✅ | ✅ | ❌ | ❌ |
| Express | ✅ | ❌ | ✅ | ❌ |
| Fragile | ✅ | ✅ | ✅ | ❌ |
| Médical | ✅ | ✅ | ✅ | ✅ |

### Étape 3 : Facturation Automatique

Quand la commande passe au statut "Livré" :
- Un enregistrement de facturation est créé automatiquement
- Le montant est calculé selon les règles du secteur
- Une facture Odoo peut être générée

### Étape 4 : Paiement

> 💵 **Paiement en espèces uniquement**
> Le destinataire paie le livreur en espèces à la réception du colis.

---

## 4. Visualisation des Factures

### Dans Smart Delivery

**Emplacement :** Smart Delivery → Facturation

Cette interface permet de **visualiser** :
- Les commandes et leur coût
- L'entreprise qui a créé la commande
- L'état de la facture (si elle existe)
- Le statut du paiement

### Dans le module Facturation Odoo

**Emplacement :** Facturation → Factures Clients

Toutes les factures sont gérées dans le module standard Odoo :
- Création et confirmation des factures
- Impression des factures PDF
- Suivi des paiements

---

## 5. Informations sur les Factures

Chaque facture contient :

| Information | Source |
|-------------|--------|
| **Nom de l'entreprise** | L'entreprise qui a créé la commande |
| **Destinataire** | La personne qui reçoit et paie |
| **Référence commande** | Numéro de la commande de livraison |
| **Détail des lignes** | Service de livraison + Frais de distance |

---

## 6. Flux Complet

```
 1. ENTREPRISE CRÉE UNE COMMANDE
        ↓
 2. LIVREUR ASSIGNÉ
        ↓
 3. LIVRAISON EFFECTUÉE
        ↓
 4. CONDITIONS VALIDÉES
        ↓
 5. FACTURATION GÉNÉRÉE (automatique)
        ↓
 6. DESTINATAIRE PAIE EN ESPÈCES
        ↓
 7. COMMANDE MARQUÉE "PAYÉE"
        ↓
 8. TERMINÉ ✓
```

---
---
---

# 🇲🇷 العربية

---

## 1. نظرة عامة على النظام

يتضمن نظام Smart Delivery نظام فوترة بسيط وفعال:

- **أسعار قابلة للتعديل**: التعريفات محددة في قواعد القطاعات
- **الدفع عند الاستلام**: المستلم يدفع نقداً
- **فواتير Odoo**: استخدام وحدة الفوترة القياسية في Odoo
- **الفوترة باسم المؤسسة**: كل فاتورة تصدر باسم المؤسسة التي أنشأت الطلب

### سير العمل الرئيسي

```
الطلب ← التوصيل ← الفوترة التلقائية ← الدفع نقداً
```

> 💰 **طريقة الدفع الوحيدة:** نقداً عند التسليم (COD)

---

## 2. إعداد التعريفات

### أين يتم تحديد الأسعار؟

**الموقع:** Smart Delivery ← الإعدادات ← قواعد القطاعات

لكل نوع قطاع، يمكنك تحديد:

| المعامل | الوصف |
|---------|-------|
| **السعر الأساسي** | التعريفة الثابتة لهذا النوع من التوصيل |
| **الرسوم لكل كم** | التكلفة لكل كيلومتر بعد المسافة المجانية |
| **المسافة المجانية** | الكيلومترات المشمولة في السعر الأساسي (افتراضي: 5 كم) |

### التعريفات الافتراضية

| نوع القطاع | السعر الأساسي | الرسوم/كم | كم مجانية |
|------------|---------------|-----------|-----------|
| عادي | 50 أوقية | 10 أوقية | 5 كم |
| متميز | 100 أوقية | 10 أوقية | 5 كم |
| سريع | 150 أوقية | 15 أوقية | 5 كم |
| هش | 120 أوقية | 12 أوقية | 5 كم |
| طبي | 200 أوقية | 20 أوقية | 5 كم |

### صيغة الحساب

```
رسوم المسافة = max(0, المسافة - كم_مجانية) × الرسوم_لكل_كم
الإجمالي = السعر الأساسي + رسوم المسافة
```

**مثال:** توصيل سريع لمسافة 12 كم
- السعر الأساسي = 150 أوقية
- رسوم المسافة = (12 - 5) × 15 = 105 أوقية
- **الإجمالي = 255 أوقية (يدفع نقداً عند التسليم)**

---

## 3. مراحل العملية

### المرحلة 1: إنشاء الطلب

**من قبل:** المؤسسة (عبر الواجهة أو API)

- المؤسسة تنشئ طلب توصيل
- نوع القطاع يحدد التعريفات تلقائياً
- المسافة تُحسب تلقائياً

### المرحلة 2: التوصيل

السائق يقوم بالتوصيل ويتحقق من الشروط المطلوبة:

| النوع | OTP | توقيع | صورة | بصمة |
|-------|-----|-------|------|------|
| عادي | ❌ | ❌ | ❌ | ❌ |
| متميز | ✅ | ✅ | ❌ | ❌ |
| سريع | ✅ | ❌ | ✅ | ❌ |
| هش | ✅ | ✅ | ✅ | ❌ |
| طبي | ✅ | ✅ | ✅ | ✅ |

### المرحلة 3: الفوترة التلقائية

عندما يتغير حالة الطلب إلى "تم التوصيل":
- يتم إنشاء سجل فوترة تلقائياً
- يُحسب المبلغ وفقاً لقواعد القطاع
- يمكن إنشاء فاتورة Odoo

### المرحلة 4: الدفع

> 💵 **الدفع نقداً فقط**
> المستلم يدفع للسائق نقداً عند استلام الطرد.

---

## 4. عرض الفواتير

### في Smart Delivery

**الموقع:** Smart Delivery ← الفوترة

هذه الواجهة تسمح **بعرض**:
- الطلبات وتكلفتها
- المؤسسة التي أنشأت الطلب
- حالة الفاتورة (إذا كانت موجودة)
- حالة الدفع

### في وحدة الفوترة Odoo

**الموقع:** الفوترة ← فواتير العملاء

جميع الفواتير تُدار في وحدة Odoo القياسية:
- إنشاء وتأكيد الفواتير
- طباعة الفواتير PDF
- متابعة المدفوعات

---

## 5. معلومات الفاتورة

كل فاتورة تحتوي على:

| المعلومة | المصدر |
|----------|--------|
| **اسم المؤسسة** | المؤسسة التي أنشأت الطلب |
| **المستلم** | الشخص الذي يستلم ويدفع |
| **مرجع الطلب** | رقم طلب التوصيل |
| **تفاصيل البنود** | خدمة التوصيل + رسوم المسافة |

---

## 6. سير العمل الكامل

```
 1. المؤسسة تنشئ طلباً
        ↓
 2. تعيين السائق
        ↓
 3. تنفيذ التوصيل
        ↓
 4. التحقق من الشروط
        ↓
 5. إنشاء الفوترة (تلقائي)
        ↓
 6. المستلم يدفع نقداً
        ↓
 7. الطلب يُحدد كـ "مدفوع"
        ↓
 8. منتهي ✓
```

---

**Smart Delivery Team**
Version 18.0.1.2.1

*هذا المستند تم إنشاؤه تلقائياً من نظام Smart Delivery*
