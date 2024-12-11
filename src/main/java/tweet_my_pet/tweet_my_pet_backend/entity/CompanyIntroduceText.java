package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "company_introduce_text")
public class CompanyIntroduceText {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "company_introduce_text_id", nullable = false)
    private Long companyIntroduceTextId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_introduce_id", nullable = false)
    private CompanyIntroduce companyIntroduce;

    @Column(name = "company_introduce_text_content", nullable = false, length = Integer.MAX_VALUE)
    private String companyIntroduceTextContent;

}