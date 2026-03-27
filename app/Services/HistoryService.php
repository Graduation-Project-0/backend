<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

class HistoryService
{
    public static function createHistory(User $user, string $scanType, string $result, array $data): Model
    {
        return $user->history()->create([
            'user_id' => $user->id,
            'scan_type' => $scanType,
            'result' => $result,
            'data' => $data,
        ]);
    }
}