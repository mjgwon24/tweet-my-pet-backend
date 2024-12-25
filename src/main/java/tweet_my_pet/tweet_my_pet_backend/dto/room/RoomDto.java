package tweet_my_pet.tweet_my_pet_backend.dto.room;

import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.room.Room;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;

public class RoomDto {
    // 방 등록 요청
    @Builder
    public record CreateRoomRequest(
            String roomType,
            int pricePerNight,
            int totalRoomCount,
            String availablePeoplePets,
            String roomDescription
    ) {
        public Room toEntity(Store store) {
            return Room.builder()
                    .roomType(this.roomType)
                    .pricePerNight(this.pricePerNight)
                    .totalRoomCount(this.totalRoomCount)
                    .availablePeoplePets(this.availablePeoplePets)
                    .roomDescription(this.roomDescription)
                    .store(store)
                    .build();
        }
    }

    // 방 단일 조회 응답
    @Builder
    public record FetchRoomResponse(
            Long id,
            String roomType,
            int pricePerNight,
            int totalRoomCount,
            String availablePeoplePets,
            String roomDescription
    ) {}
}
