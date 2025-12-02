<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('plans', function (Blueprint $table) {
            $table->id();
            
            // Core Fields
            $table->string('name');
            $table->string('slug')->unique();
            $table->text('description')->nullable();
            $table->string('plan_type')->index(); // free, essential, premium, enterprise
            $table->string('icon')->nullable();
            $table->string('badge')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->integer('sort_order')->default(0);
            
            // Pricing Fields
            $table->decimal('price', 10, 2)->nullable();
            $table->string('billing_period')->nullable(); // monthly, yearly, lifetime
            $table->integer('trial_days')->nullable()->default(0);
            
            // Configuration Fields
            $table->integer('max_devices')->nullable();
            $table->integer('duration_months')->nullable();
            
            // Features & Metadata
            $table->json('features')->nullable();
            $table->json('metadata')->nullable();
            
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('plans');
    }
};
