package tweet_my_pet.tweet_my_pet_backend.exception;

/**
 * 중복 예외 처리
 */
public class DuplicateResourceException extends RuntimeException{
    public DuplicateResourceException(String message) {
        super(message);
    }
}
