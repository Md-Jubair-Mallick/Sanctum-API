<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\HasApiTokens;

class Post extends Model
{
    use HasApiTokens, HasUuids;

    protected $fillable = [
        'title',
        'description',
        ];
}