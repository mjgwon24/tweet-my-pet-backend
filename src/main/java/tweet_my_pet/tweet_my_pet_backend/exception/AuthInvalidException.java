package tweet_my_pet.tweet_my_pet_backend.exception;

public class AuthInvalidException extends AuthException {
    public AuthInvalidException(String message) {
        super(message);
    }

    public AuthInvalidException(String message, Throwable cause) {
        super(message, cause);
    }
}