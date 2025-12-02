<?php

namespace App\Support\Services;

use App\Models\History;
use App\Models\User;

class HistoryService
{
    public function createHistory(User|int $user, string $scanType, string $result, array $data): History
    {
        return History::query()
            ->create([
                'user_id' => $user instanceof User ? $user->id : $user,
                'scan_type' => $scanType,
                'result' => $result,
                'data' => $data,
            ]);
    }
}
