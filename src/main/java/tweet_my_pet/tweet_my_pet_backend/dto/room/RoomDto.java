package tweet_my_pet.tweet_my_pet_backend.dto.room;

import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;

public class RoomDto {
    // 방 추가 요청
    @Builder
    public record AddRoomRequest(
            String roomType,
            int pricePerNight,
            int totalRoomCount
    ) {
        @Builder
        public Room toEntity(Store store) {
            return Room.builder()
                    .roomType(this.roomType)
                    .pricePerNight(this.pricePerNight)
                    .totalRoomCount(this.totalRoomCount)
                    .store(store)
                    .build();
        }
    }

    // 방 추가 응답
    @Builder
    public record AddRoomResponse(
            Long id,
            String roomType,
            int pricePerNight,
            int totalRoomCount
    ) {}
}
