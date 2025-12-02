<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Plan extends Model
{
    // Plan Type Constants
    public const TYPE_FREE = 'free';
    public const TYPE_ESSENTIAL = 'essential';
    public const TYPE_PREMIUM = 'premium';
    public const TYPE_ENTERPRISE = 'enterprise';

    // Billing Period Constants
    public const BILLING_MONTHLY = 'monthly';
    public const BILLING_YEARLY = 'yearly';
    public const BILLING_LIFETIME = 'lifetime';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $guarded = [];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
            'sort_order' => 'integer',
            'price' => 'decimal:2',
            'trial_days' => 'integer',
            'max_devices' => 'integer',
            'duration_months' => 'integer',
            'features' => 'array',
            'metadata' => 'array',
        ];
    }

    /**
     * Check if the plan is active.
     */
    public function isActive(): bool
    {
        return $this->is_active === true;
    }

    /**
     * Check if the plan includes a specific feature.
     */
    public function hasFeature(string $featureName): bool
    {
        $features = $this->features ?? [];
        
        if (is_array($features)) {
            return in_array($featureName, $features, true);
        }

        return false;
    }

    /**
     * Get formatted price with dollar sign.
     */
    public function getFormattedPrice(): ?string
    {
        if ($this->price === null) {
            return null;
        }

        return '$' . number_format((float) $this->price, 2);
    }

    /**
     * Scope a query to only include active plans.
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope a query to filter by plan type.
     */
    public function scopeByType($query, string $type)
    {
        return $query->where('plan_type', $type);
    }

    /**
     * Get all plan types.
     */
    public static function getPlanTypes(): array
    {
        return [
            self::TYPE_FREE,
            self::TYPE_ESSENTIAL,
            self::TYPE_PREMIUM,
            self::TYPE_ENTERPRISE,
        ];
    }

    /**
     * Get all billing periods.
     */
    public static function getBillingPeriods(): array
    {
        return [
            self::BILLING_MONTHLY,
            self::BILLING_YEARLY,
            self::BILLING_LIFETIME,
        ];
    }

    public function users()
    {
        return $this->hasMany(User::class);
    }
    
    public function subscriptions()
    {
        return $this->hasMany(Subscription::class);
    }
}
