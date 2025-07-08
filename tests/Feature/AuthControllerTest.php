<?php

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Facades\JWTAuth;

use function Pest\Laravel\postJson;
use function Pest\Laravel\getJson;
use function Pest\Laravel\putJson;

uses(\Illuminate\Foundation\Testing\RefreshDatabase::class);

it('registers a user', function () {
    $response = postJson('/api/register', [
        'name' => 'Test User',
        'email' => 'test' . Str::random(5) . '@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ]);

    $response->assertCreated()
        ->assertJsonStructure([
            'token',
            'user' => ['id', 'name', 'email', 'created_at', 'updated_at'],
        ]);

    expect(User::where('email', $response['user']['email'])->exists())->toBeTrue();
});

it('logs in a user with correct credentials', function () {
    $user = User::factory()->create([
        'password' => Hash::make('password'),
    ]);

    $response = postJson('/api/login', [
        'email' => $user->email,
        'password' => 'password',
    ]);

    $response->assertOk()
        ->assertJsonStructure([
            'token',
            'expires_in',
        ]);
});

it('fails to log in with wrong credentials', function () {
    $user = User::factory()->create([
        'password' => Hash::make('password'),
    ]);

    $response = postJson('/api/login', [
        'email' => $user->email,
        'password' => 'wrong-password',
    ]);

    $response->assertStatus(401)
        ->assertJson(['error' => 'Invalid credentials']);
});

it('gets the authenticated user', function () {
    $user = User::factory()->create();
    $token = JWTAuth::fromUser($user);

    $response = getJson('/api/user', [
        'Authorization' => "Bearer $token",
    ]);

    $response->assertOk()
        ->assertJson([
            'id' => $user->id,
            'email' => $user->email,
        ]);
});

it('returns 404 if user is not authenticated when fetching user', function () {
    $response = getJson('/api/user');

    $response->assertStatus(401); // Laravel's default for unauthenticated
});

it('updates the authenticated user', function () {
    $user = User::factory()->create();
    $token = JWTAuth::fromUser($user);

    $newEmail = 'updated' . Str::random(5) . '@example.com';

    $response = putJson('/api/user', [
        'name' => 'Updated Name',
        'email' => $newEmail,
    ], [
        'Authorization' => "Bearer $token",
    ]);

    $response->assertOk()
        ->assertJson([
            'id' => $user->id,
            'name' => 'Updated Name',
            'email' => $newEmail,
        ]);

    expect(User::find($user->id)->email)->toBe($newEmail);
});

it('logs out the user', function () {
    $user = User::factory()->create();
    $token = JWTAuth::fromUser($user);

    $response = postJson('/api/logout', [], [
        'Authorization' => "Bearer $token",
    ]);

    $response->assertOk()
        ->assertJson([
            'message' => 'Successfully logged out',
        ]);
});
