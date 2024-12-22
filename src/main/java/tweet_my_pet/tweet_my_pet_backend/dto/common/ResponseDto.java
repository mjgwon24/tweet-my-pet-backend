package tweet_my_pet.tweet_my_pet_backend.dto.common;

import ch.qos.logback.core.status.Status;

public record ResponseDto<T> (
        Status status,
        String msg,
        T data
){
    public enum Status {
        SUCCESS, FAILURE
    }
}
